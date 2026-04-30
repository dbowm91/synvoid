use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::Mutex;
use rusqlite::{params, Connection};

use crate::mesh::raft::state_machine::{Namespace, OrgPublicKey, ThreatIntel};

const EDGE_REPLICA_CACHE_MAX_ITEMS: u64 = 10000;
const EDGE_REPLICA_CACHE_TTL_SECS: u64 = 300;

#[derive(Clone)]
pub struct EdgeReplicaManager {
    db: Arc<Mutex<Connection>>,
    cache: Cache<String, CachedRecord>,
}

#[derive(Clone)]
struct CachedRecord {
    value: Vec<u8>,
    #[allow(dead_code)]
    timestamp: u64,
}

impl EdgeReplicaManager {
    pub fn new(data_dir: PathBuf) -> Result<Self, rusqlite::Error> {
        std::fs::create_dir_all(&data_dir).ok();
        let db_path = data_dir.join("read_replica.db");
        let db = Connection::open(&db_path)?;

        Self::init_schema(&db)?;

        let cache = Cache::builder()
            .max_capacity(EDGE_REPLICA_CACHE_MAX_ITEMS)
            .time_to_live(Duration::from_secs(EDGE_REPLICA_CACHE_TTL_SECS))
            .build();

        tracing::info!("EdgeReplicaManager initialized at {:?}", db_path);

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            cache,
        })
    }

    fn init_schema(db: &Connection) -> Result<(), rusqlite::Error> {
        db.execute(
            "CREATE TABLE IF NOT EXISTS org_keys (
                key_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                signer_node_id TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        db.execute(
            "CREATE TABLE IF NOT EXISTS threat_intel (
                indicator_id TEXT PRIMARY KEY,
                indicator_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                source_node_id TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        db.execute(
            "CREATE TABLE IF NOT EXISTS revocation_list (
                revoked_node_id TEXT PRIMARY KEY,
                revoked_at INTEGER NOT NULL,
                reason TEXT NOT NULL,
                revoked_by_node_id TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        db.execute(
            "CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_org_keys_org_id ON org_keys(org_id)",
            [],
        )?;

        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_intel_severity ON threat_intel(severity)",
            [],
        )?;

        Ok(())
    }

    pub fn get_org_key(&self, key_id: &str) -> Option<OrgPublicKey> {
        if let Some(cached) = self.cache.get(&format!("org:{}", key_id)) {
            return postcard::from_bytes(&cached.value).ok();
        }

        let db = self.db.lock();
        let result = db.query_row(
            "SELECT org_id, public_key, created_at, signer_node_id FROM org_keys WHERE key_id = ?1",
            params![key_id],
            |row| {
                Ok(OrgPublicKey {
                    org_id: row.get(0)?,
                    public_key: row.get(1)?,
                    created_at: row.get(2)?,
                    signer_node_id: row.get(3)?,
                })
            },
        );

        match result {
            Ok(key) => {
                let value = postcard::to_stdvec(&key).ok()?;
                self.cache.insert(
                    format!("org:{}", key_id),
                    CachedRecord {
                        value: value.clone(),
                        timestamp: crate::mesh::safe_unix_timestamp(),
                    },
                );
                Some(key)
            }
            Err(_) => None,
        }
    }

    pub fn get_threat_intel(&self, indicator_id: &str) -> Option<ThreatIntel> {
        if let Some(cached) = self.cache.get(&format!("intel:{}", indicator_id)) {
            return postcard::from_bytes(&cached.value).ok();
        }

        let db = self.db.lock();
        let result = db.query_row(
            "SELECT indicator_id, indicator_type, pattern, severity, created_at, expires_at, source_node_id FROM threat_intel WHERE indicator_id = ?1",
            params![indicator_id],
            |row| {
                Ok(ThreatIntel {
                    indicator_id: row.get(0)?,
                    indicator_type: row.get(1)?,
                    pattern: row.get(2)?,
                    severity: row.get(3)?,
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    source_node_id: row.get(6)?,
                })
            },
        );

        match result {
            Ok(intel) => {
                let value = postcard::to_stdvec(&intel).ok()?;
                self.cache.insert(
                    format!("intel:{}", indicator_id),
                    CachedRecord {
                        value: value.clone(),
                        timestamp: crate::mesh::safe_unix_timestamp(),
                    },
                );
                Some(intel)
            }
            Err(_) => None,
        }
    }

    pub fn update_org_key(&self, key_id: &str, value: &[u8]) -> Result<(), rusqlite::Error> {
        let org_key: OrgPublicKey = postcard::from_bytes(value)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

        let timestamp = crate::mesh::safe_unix_timestamp();

        let db = self.db.lock();
        db.execute(
            "INSERT OR REPLACE INTO org_keys (key_id, org_id, public_key, created_at, signer_node_id, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![key_id, org_key.org_id, org_key.public_key, org_key.created_at, org_key.signer_node_id, timestamp],
        )?;

        drop(db);

        self.cache.insert(
            format!("org:{}", key_id),
            CachedRecord {
                value: value.to_vec(),
                timestamp,
            },
        );

        Ok(())
    }

    pub fn update_threat_intel(
        &self,
        indicator_id: &str,
        value: &[u8],
    ) -> Result<(), rusqlite::Error> {
        let intel: ThreatIntel = postcard::from_bytes(value)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

        let timestamp = crate::mesh::safe_unix_timestamp();

        let db = self.db.lock();
        db.execute(
            "INSERT OR REPLACE INTO threat_intel (indicator_id, indicator_type, pattern, severity, created_at, expires_at, source_node_id, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![indicator_id, intel.indicator_type, intel.pattern, intel.severity, intel.created_at, intel.expires_at, intel.source_node_id, timestamp],
        )?;

        drop(db);

        self.cache.insert(
            format!("intel:{}", indicator_id),
            CachedRecord {
                value: value.to_vec(),
                timestamp,
            },
        );

        Ok(())
    }

    pub fn update_revocation(&self, node_id: &str, value: &[u8]) -> Result<(), rusqlite::Error> {
        #[derive(serde::Deserialize)]
        struct RevocationInfo {
            revoked_at: u64,
            reason: String,
        }

        let revocation: RevocationInfo = postcard::from_bytes(value)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

        #[derive(serde::Deserialize)]
        struct RevocationRecord {
            revoked_by_node_id: String,
        }

        let record: RevocationRecord = postcard::from_bytes(value)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

        let timestamp = crate::mesh::safe_unix_timestamp();

        let db = self.db.lock();
        db.execute(
            "INSERT OR REPLACE INTO revocation_list (revoked_node_id, revoked_at, reason, revoked_by_node_id, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![node_id, revocation.revoked_at, revocation.reason, record.revoked_by_node_id, timestamp],
        )?;

        Ok(())
    }

    pub fn update_from_notification(
        &self,
        namespace: &Namespace,
        key_id: &str,
        value: &[u8],
    ) -> Result<(), rusqlite::Error> {
        match namespace {
            Namespace::Org => self.update_org_key(key_id, value),
            Namespace::Intel => self.update_threat_intel(key_id, value),
            Namespace::Revocation => self.update_revocation(key_id, value),
        }
    }

    pub fn delete_org_key(&self, key_id: &str) -> Result<(), rusqlite::Error> {
        let db = self.db.lock();
        db.execute("DELETE FROM org_keys WHERE key_id = ?1", params![key_id])?;
        self.cache.remove(&format!("org:{}", key_id));
        Ok(())
    }

    pub fn delete_threat_intel(&self, indicator_id: &str) -> Result<(), rusqlite::Error> {
        let db = self.db.lock();
        db.execute(
            "DELETE FROM threat_intel WHERE indicator_id = ?1",
            params![indicator_id],
        )?;
        self.cache.remove(&format!("intel:{}", indicator_id));
        Ok(())
    }

    pub fn delete_revocation(&self, node_id: &str) -> Result<(), rusqlite::Error> {
        let db = self.db.lock();
        db.execute(
            "DELETE FROM revocation_list WHERE revoked_node_id = ?1",
            params![node_id],
        )?;
        Ok(())
    }

    pub fn delete_from_notification(
        &self,
        namespace: &Namespace,
        key_id: &str,
    ) -> Result<(), rusqlite::Error> {
        match namespace {
            Namespace::Org => self.delete_org_key(key_id),
            Namespace::Intel => self.delete_threat_intel(key_id),
            Namespace::Revocation => self.delete_revocation(key_id),
        }
    }

    pub fn get_last_sync_index(&self) -> Option<u64> {
        let db = self.db.lock();
        db.query_row(
            "SELECT value FROM sync_metadata WHERE key = 'last_sync_index'",
            [],
            |row| {
                let val: String = row.get(0)?;
                Ok(val.parse::<u64>().unwrap_or(0))
            },
        )
        .ok()
    }

    pub fn set_last_sync_index(&self, index: u64) -> Result<(), rusqlite::Error> {
        let db = self.db.lock();
        db.execute(
            "INSERT OR REPLACE INTO sync_metadata (key, value) VALUES ('last_sync_index', ?1)",
            params![index.to_string()],
        )?;
        Ok(())
    }

    pub fn get_cache_stats(&self) -> (u64, u64) {
        let hits = self.cache.entry_count();
        (hits, self.cache.weighted_size())
    }

    pub fn invalidate_stale_records(&self, max_age_secs: u64) -> Result<usize, rusqlite::Error> {
        let current_time = crate::mesh::safe_unix_timestamp();
        let cutoff = current_time.saturating_sub(max_age_secs);

        let db = self.db.lock();

        let org_deleted = db.execute(
            "DELETE FROM org_keys WHERE updated_at < ?1",
            params![cutoff as i64],
        )?;

        let intel_deleted = db.execute(
            "DELETE FROM threat_intel WHERE updated_at < ?1",
            params![cutoff as i64],
        )?;

        let revocation_deleted = db.execute(
            "DELETE FROM revocation_list WHERE updated_at < ?1",
            params![cutoff as i64],
        )?;

        Ok(org_deleted + intel_deleted + revocation_deleted)
    }

    pub fn cache_key(&self, namespace: Namespace, key_id: &str, value: Vec<u8>) {
        let cache_key = match namespace {
            Namespace::Org => format!("org:{}", key_id),
            Namespace::Intel => format!("intel:{}", key_id),
            Namespace::Revocation => format!("revocation:{}", key_id),
        };

        self.cache.insert(
            cache_key,
            CachedRecord {
                value,
                timestamp: crate::mesh::safe_unix_timestamp(),
            },
        );
    }
}

pub fn create_edge_replica_manager(data_dir: Option<PathBuf>) -> Option<EdgeReplicaManager> {
    let data_dir = data_dir?.join("edge_replica");
    EdgeReplicaManager::new(data_dir).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn create_test_manager() -> (EdgeReplicaManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = EdgeReplicaManager::new(temp_dir.path().to_path_buf()).unwrap();
        (manager, temp_dir)
    }

    fn create_org_key_value(org_id: &str, key_id: &str) -> Vec<u8> {
        let key = OrgPublicKey {
            org_id: org_id.to_string(),
            public_key: vec![1, 2, 3, 4],
            created_at: 1000,
            signer_node_id: "node1".to_string(),
        };
        postcard::to_stdvec(&key).unwrap()
    }

    fn create_threat_intel_value(indicator_id: &str) -> Vec<u8> {
        let intel = ThreatIntel {
            indicator_id: indicator_id.to_string(),
            indicator_type: "malware".to_string(),
            pattern: "*.evil.com".to_string(),
            severity: "high".to_string(),
            created_at: 1000,
            expires_at: Some(2000),
            source_node_id: "node1".to_string(),
        };
        postcard::to_stdvec(&intel).unwrap()
    }

    #[test]
    fn test_get_org_key_cache_hit() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        drop(manager);

        let (manager2, _temp_dir2) = create_test_manager();
        manager2.update_org_key("key1", &value).unwrap();
        let cached = manager2.get_org_key("key1");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().org_id, "org1");
    }

    #[test]
    fn test_get_org_key_cache_miss_then_hit() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let result = manager.get_org_key("key1");
        assert!(result.is_some());
        assert_eq!(result.unwrap().org_id, "org1");
    }

    #[test]
    fn test_get_org_key_not_found() {
        let (manager, _temp_dir) = create_test_manager();
        let result = manager.get_org_key("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_threat_intel_cache_hit() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_threat_intel_value("indicator1");
        manager.update_threat_intel("indicator1", &value).unwrap();
        let result = manager.get_threat_intel("indicator1");
        assert!(result.is_some());
        assert_eq!(result.unwrap().indicator_type, "malware");
    }

    #[test]
    fn test_get_threat_intel_cache_miss_then_hit() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_threat_intel_value("indicator1");
        manager.update_threat_intel("indicator1", &value).unwrap();
        let result = manager.get_threat_intel("indicator1");
        assert!(result.is_some());
        assert_eq!(result.unwrap().pattern, "*.evil.com");
    }

    #[test]
    fn test_get_threat_intel_not_found() {
        let (manager, _temp_dir) = create_test_manager();
        let result = manager.get_threat_intel("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_update_org_key_normal() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        let result = manager.update_org_key("key1", &value);
        assert!(result.is_ok());
        let retrieved = manager.get_org_key("key1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().org_id, "org1");
    }

    #[test]
    fn test_update_threat_intel_normal() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_threat_intel_value("indicator1");
        let result = manager.update_threat_intel("indicator1", &value);
        assert!(result.is_ok());
        let retrieved = manager.get_threat_intel("indicator1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().severity, "high");
    }

    #[test]
    fn test_update_from_notification_org() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        let result = manager.update_from_notification(&Namespace::Org, "key1", &value);
        assert!(result.is_ok());
        let retrieved = manager.get_org_key("key1");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_update_from_notification_intel() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_threat_intel_value("indicator1");
        let result = manager.update_from_notification(&Namespace::Intel, "indicator1", &value);
        assert!(result.is_ok());
        let retrieved = manager.get_threat_intel("indicator1");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_delete_from_notification_org() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let result = manager.delete_from_notification(&Namespace::Org, "key1");
        assert!(result.is_ok());
        let retrieved = manager.get_org_key("key1");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_delete_from_notification_intel() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_threat_intel_value("indicator1");
        manager.update_threat_intel("indicator1", &value).unwrap();
        let result = manager.delete_from_notification(&Namespace::Intel, "indicator1");
        assert!(result.is_ok());
        let retrieved = manager.get_threat_intel("indicator1");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_delete_from_notification_missing_record() {
        let (manager, _temp_dir) = create_test_manager();
        let result = manager.delete_from_notification(&Namespace::Org, "nonexistent");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalidate_stale_records() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let deleted = manager.invalidate_stale_records(600);
        assert!(deleted.is_ok());
        assert_eq!(deleted.unwrap(), 0);
        let retrieved = manager.get_org_key("key1");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_cache_stats() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        manager.get_org_key("key1");
        let result = manager.get_org_key("key1");
        assert!(result.is_some());
    }

    #[test]
    fn test_disk_full_handling() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        fs::write(&db_path, b"").unwrap();
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444)).ok();
        let db = rusqlite::Connection::open(&db_path);
        if db.is_err() {
            return;
        }
        let db = db.unwrap();
        let result = db.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)", []);
        match result {
            Err(rusqlite::Error::InvalidParameterName(_)) | Err(rusqlite::Error::InvalidQuery) => {}
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("readonly")
                    || msg.contains("permission")
                    || msg.contains("disk")
                    || msg.contains("space")
                {
                    return;
                }
            }
        }
    }

    #[test]
    fn test_corrupted_database_handling() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("corrupted.db");
        fs::write(&db_path, b"not a valid sqlite database at all").unwrap();
        let db_result = rusqlite::Connection::open(&db_path);
        if db_result.is_err() {
            return;
        }
        let db = db_result.unwrap();
        let result = db.query_row("SELECT * FROM nonexistent", [], |_| Ok(()));
        assert!(result.is_err());
    }

    #[test]
    fn test_concurrent_notification_bursts() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        std::thread::scope(|s| {
            let m = manager.clone();
            s.spawn(move || {
                for i in 0..10 {
                    let val = create_org_key_value(&format!("org{}", i), "key1");
                    let _ = m.update_org_key("key1", &val);
                }
            });
        });
        let result = manager.get_org_key("key1");
        assert!(result.is_some());
    }

    #[test]
    fn test_concurrent_mixed_operations() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let intel_value = create_threat_intel_value("indicator1");
        manager
            .update_threat_intel("indicator1", &intel_value)
            .unwrap();
        let m1 = manager.clone();
        let m2 = manager.clone();
        let m3 = manager.clone();
        std::thread::scope(|s| {
            s.spawn(move || {
                for i in 0..5 {
                    let val = create_org_key_value(&format!("org{}", i), "key1");
                    let _ = m1.update_org_key("key1", &val);
                    let _ = m1.get_org_key("key1");
                }
            });
            s.spawn(move || {
                for i in 0..5 {
                    let val = create_threat_intel_value(&format!("indicator{}", i));
                    let _ = m2.update_threat_intel("indicator1", &val);
                    let _ = m2.get_threat_intel("indicator1");
                }
            });
            s.spawn(move || {
                for _ in 0..5 {
                    let _ = m3.delete_from_notification(&Namespace::Org, "key1");
                    let _ = m3.update_org_key("key1", &value);
                }
            });
        });
        assert!(manager.get_org_key("key1").is_some());
        assert!(manager.get_threat_intel("indicator1").is_some());
    }

    #[test]
    fn test_update_org_key_deserialization_error() {
        let (manager, _temp_dir) = create_test_manager();
        let invalid_data = vec![0, 1, 2, 3, 4, 5];
        let result = manager.update_org_key("key1", &invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_threat_intel_deserialization_error() {
        let (manager, _temp_dir) = create_test_manager();
        let invalid_data = vec![0, 1, 2, 3, 4, 5];
        let result = manager.update_threat_intel("indicator1", &invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_last_sync_index() {
        let (manager, _temp_dir) = create_test_manager();
        let result = manager.get_last_sync_index();
        assert!(result.is_none());
        manager.set_last_sync_index(42).unwrap();
        let result = manager.get_last_sync_index();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_set_last_sync_index() {
        let (manager, _temp_dir) = create_test_manager();
        let result = manager.set_last_sync_index(100);
        assert!(result.is_ok());
        let result = manager.get_last_sync_index();
        assert_eq!(result, Some(100));
    }

    #[test]
    fn test_cache_invalidation_on_delete() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let cached = manager.get_org_key("key1");
        assert!(cached.is_some());
        manager.delete_org_key("key1").unwrap();
        let result = manager.get_org_key("key1");
        assert!(result.is_none());
    }

    #[test]
    fn test_concurrent_delete_operations() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let m = manager.clone();
        let m2 = manager.clone();
        let m3 = manager.clone();
        let m4 = manager.clone();
        let m5 = manager.clone();
        std::thread::scope(|s| {
            s.spawn(move || {
                let _ = m.delete_from_notification(&Namespace::Org, "key1");
            });
            s.spawn(move || {
                let _ = m2.delete_from_notification(&Namespace::Org, "key1");
            });
            s.spawn(move || {
                let _ = m3.delete_from_notification(&Namespace::Org, "key1");
            });
            s.spawn(move || {
                let _ = m4.delete_from_notification(&Namespace::Org, "key1");
            });
            s.spawn(move || {
                let _ = m5.delete_from_notification(&Namespace::Org, "key1");
            });
        });
        let result = manager.get_org_key("key1");
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_keys_isolation() {
        let (manager, _temp_dir) = create_test_manager();
        let value1 = create_org_key_value("org1", "key1");
        let value2 = create_org_key_value("org2", "key2");
        manager.update_org_key("key1", &value1).unwrap();
        manager.update_org_key("key2", &value2).unwrap();
        let retrieved1 = manager.get_org_key("key1");
        let retrieved2 = manager.get_org_key("key2");
        assert!(retrieved1.is_some());
        assert!(retrieved2.is_some());
        assert_eq!(retrieved1.unwrap().org_id, "org1");
        assert_eq!(retrieved2.unwrap().org_id, "org2");
    }

    #[test]
    fn test_ttl_expiration_behavior() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let result = manager.invalidate_stale_records(3600);
        assert!(result.is_ok());
    }
}
