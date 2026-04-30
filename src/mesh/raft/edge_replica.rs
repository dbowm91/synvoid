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

        tracing::info!(
            "EdgeReplicaManager initialized at {:?}",
            db_path
        );

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
                self.cache.insert(format!("org:{}", key_id), CachedRecord {
                    value: value.clone(),
                    timestamp: crate::mesh::safe_unix_timestamp(),
                });
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
                self.cache.insert(format!("intel:{}", indicator_id), CachedRecord {
                    value: value.clone(),
                    timestamp: crate::mesh::safe_unix_timestamp(),
                });
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

    pub fn update_threat_intel(&self, indicator_id: &str, value: &[u8]) -> Result<(), rusqlite::Error> {
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
        db.execute("DELETE FROM threat_intel WHERE indicator_id = ?1", params![indicator_id])?;
        self.cache.remove(&format!("intel:{}", indicator_id));
        Ok(())
    }

    pub fn delete_revocation(&self, node_id: &str) -> Result<(), rusqlite::Error> {
        let db = self.db.lock();
        db.execute("DELETE FROM revocation_list WHERE revoked_node_id = ?1", params![node_id])?;
        Ok(())
    }

    pub fn delete_from_notification(&self, namespace: &Namespace, key_id: &str) -> Result<(), rusqlite::Error> {
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

pub fn create_edge_replica_manager(
    data_dir: Option<PathBuf>,
) -> Option<EdgeReplicaManager> {
    let data_dir = data_dir?.join("edge_replica");
    EdgeReplicaManager::new(data_dir).ok()
}
