use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use openraft::RaftTypeConfig;
use openraft::type_config::alias::{LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf};
use openraft::vote::leader_id_std::LeaderId;
use openraft::vote::RaftLeaderId;
use rusqlite::{params, Connection};

pub type NodeId = u64;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
pub enum Namespace {
    Org,
    Intel,
    Revocation,
}

impl Namespace {
    pub fn as_str(&self) -> &'static str {
        match self {
            Namespace::Org => "org",
            Namespace::Intel => "intel",
            Namespace::Revocation => "revocation",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "org" => Some(Namespace::Org),
            "intel" => Some(Namespace::Intel),
            "revocation" => Some(Namespace::Revocation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrgPublicKey {
    pub org_id: String,
    pub public_key: Vec<u8>,
    pub created_at: u64,
    pub signer_node_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatIntel {
    pub indicator_id: String,
    pub indicator_type: String,
    pub pattern: String,
    pub severity: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub source_node_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GlobalNodeRevocationList {
    pub revoked_node_ids: Vec<String>,
    pub revoked_at: u64,
    pub revoked_by_node_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum StateMachineValue {
    Org(OrgPublicKey),
    Intel(ThreatIntel),
    Revocation(GlobalNodeRevocationList),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RaftCommand {
    Set { namespace: Namespace, key: String, value: Vec<u8> },
    Delete { namespace: Namespace, key: String },
}

pub struct GlobalRegistryStateMachine {
    db: Arc<Mutex<Connection>>,
}

unsafe impl Send for GlobalRegistryStateMachine {}
unsafe impl Sync for GlobalRegistryStateMachine {}

impl GlobalRegistryStateMachine {
    pub fn new(db_path: PathBuf) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Self::init_schema(&db)?;
        Ok(Self { db: Arc::new(Mutex::new(db)) })
    }

    fn init_schema(db: &Connection) -> Result<(), rusqlite::Error> {
        db.execute(
            "CREATE TABLE IF NOT EXISTS state_machine (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value BLOB NOT NULL,
                PRIMARY KEY (namespace, key)
            )",
            [],
        )?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS snapshot_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    pub fn get(&self, namespace: &Namespace, key: &str) -> Option<Vec<u8>> {
        self.db.lock().unwrap()
            .query_row(
                "SELECT value FROM state_machine WHERE namespace = ?1 AND key = ?2",
                params![namespace.as_str(), key],
                |row| row.get(0),
            )
            .ok()
    }

    pub fn set(&self, namespace: &Namespace, key: &str, value: Vec<u8>) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO state_machine (namespace, key, value) VALUES (?1, ?2, ?3)",
            params![namespace.as_str(), key, value],
        )?;
        Ok(())
    }

    pub fn delete(&self, namespace: &Namespace, key: &str) -> Result<bool, rusqlite::Error> {
        let rows = self.db.lock().unwrap().execute(
            "DELETE FROM state_machine WHERE namespace = ?1 AND key = ?2",
            params![namespace.as_str(), key],
        )?;
        Ok(rows > 0)
    }

    pub fn get_last_applied_log_id(&self) -> Option<u64> {
        self.db.lock().unwrap()
            .query_row(
                "SELECT value FROM snapshot_metadata WHERE key = 'last_applied_log_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|s| s.split(':').last()?.parse().ok())
    }

    pub fn set_last_applied_log_id(&self, index: u64) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO snapshot_metadata (key, value) VALUES ('last_applied_log_id', ?1)",
            params![index.to_string()],
        )?;
        Ok(())
    }

    pub fn get_membership_raw(&self) -> Option<String> {
        self.db.lock().unwrap()
            .query_row(
                "SELECT value FROM snapshot_metadata WHERE key = 'last_membership'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
    }

    pub fn set_membership_raw(&self, membership_json: &str) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO snapshot_metadata (key, value) VALUES ('last_membership', ?1)",
            params![membership_json],
        )?;
        Ok(())
    }

    pub fn get_all_entries(&self) -> Vec<(Namespace, String, Vec<u8>)> {
        let db_guard = self.db.lock().unwrap();
        let mut stmt = match db_guard.prepare(
            "SELECT namespace, key, value FROM state_machine"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let entries = stmt.query_map([], |row| {
            let namespace: String = row.get(0)?;
            let key: String = row.get(1)?;
            let value: Vec<u8> = row.get(2)?;
            Ok((namespace, key, value))
        });

        match entries {
            Ok(iter) => iter.filter_map(|e| e.ok()).filter_map(|(ns, k, v)| {
                Namespace::from_str(&ns).map(|n| (n, k, v))
            }).collect(),
            Err(_) => Vec::new(),
        }
    }
}

pub struct GlobalRegistryLogStorage {
    db: Arc<Mutex<Connection>>,
}

unsafe impl Send for GlobalRegistryLogStorage {}
unsafe impl Sync for GlobalRegistryLogStorage {}

impl GlobalRegistryLogStorage {
    pub fn new(db_path: PathBuf) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Self::init_schema(&db)?;
        Ok(Self { db: Arc::new(Mutex::new(db)) })
    }

    fn init_schema(db: &Connection) -> Result<(), rusqlite::Error> {
        db.execute(
            "CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY,
                term INTEGER NOT NULL,
                payload BLOB NOT NULL,
                membership TEXT
            )",
            [],
        )?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS vote_store (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                vote BLOB NOT NULL
            )",
            [],
        )?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS snapshot_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    pub fn append_log_entry(&self, index: u64, term: u64, payload: &[u8], membership: Option<&str>) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT INTO log_entries (id, term, payload, membership) VALUES (?1, ?2, ?3, ?4)",
            params![index as i64, term as i64, payload, membership],
        )?;
        Ok(())
    }

    pub fn get_log_entry(&self, index: u64) -> Option<(u64, Vec<u8>)> {
        self.db.lock().unwrap().query_row(
            "SELECT term, payload FROM log_entries WHERE id = ?1",
            params![index as i64],
            |row| {
                let term: i64 = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((term as u64, payload))
            },
        ).ok()
    }

    pub fn save_vote(&self, vote: &[u8]) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO vote_store (id, vote) VALUES (1, ?1)",
            params![vote],
        )?;
        Ok(())
    }

    pub fn get_vote(&self) -> Option<Vec<u8>> {
        self.db.lock().unwrap().query_row(
            "SELECT vote FROM vote_store WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ).ok()
    }
}

pub struct GlobalRegistryConfig {
    pub node_id: NodeId,
    pub db_path: PathBuf,
}

pub struct GlobalRegistry<C: RaftTypeConfig> {
    config: GlobalRegistryConfig,
    state_machine: GlobalRegistryStateMachine,
    log_storage: GlobalRegistryLogStorage,
    voting_nodes: std::sync::RwLock<Vec<NodeId>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: RaftTypeConfig> GlobalRegistry<C> {
    pub fn new(config: GlobalRegistryConfig) -> Result<Self, rusqlite::Error> {
        let state_machine = GlobalRegistryStateMachine::new(config.db_path.clone())?;
        let log_storage = GlobalRegistryLogStorage::new(config.db_path.join("raft_log.db"))?;
        Ok(Self {
            config,
            state_machine,
            log_storage,
            voting_nodes: std::sync::RwLock::new(Vec::new()),
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn get_voting_nodes(&self) -> Vec<NodeId> {
        self.voting_nodes.read().unwrap().clone()
    }

    pub fn set_voting_nodes(&self, nodes: Vec<NodeId>) {
        *self.voting_nodes.write().unwrap() = nodes;
    }

    pub fn get_value(&self, namespace: &Namespace, key: &str) -> Option<Vec<u8>> {
        self.state_machine.get(namespace, key)
    }

    pub fn set_value(&self, namespace: &Namespace, key: &str, value: Vec<u8>) -> Result<(), rusqlite::Error> {
        self.state_machine.set(namespace, key, value)
    }

    pub fn delete_value(&self, namespace: &Namespace, key: &str) -> Result<bool, rusqlite::Error> {
        self.state_machine.delete(namespace, key)
    }
}