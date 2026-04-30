use std::fmt::{Debug, Display};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use openraft::entry::RaftEntry;
use openraft::storage::EntryResponder;
use openraft::storage::RaftLogReader;
use openraft::storage::{
    IOFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine,
};
use openraft::type_config::alias::{
    EntryOf, LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf, VoteOf,
};
use openraft::vote::RaftLeaderId;
use openraft::EntryPayload;
use openraft::OptionalSend;
use openraft::RaftTypeConfig;
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
    Set {
        namespace: Namespace,
        key: String,
        value: Vec<u8>,
    },
    Delete {
        namespace: Namespace,
        key: String,
    },
}

impl Display for RaftCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaftCommand::Set { namespace, key, .. } => {
                write!(f, "RaftCommand::Set({}, {})", namespace.as_str(), key)
            }
            RaftCommand::Delete { namespace, key } => {
                write!(f, "RaftCommand::Delete({}, {})", namespace.as_str(), key)
            }
        }
    }
}

openraft::declare_raft_types!(
    pub GlobalRegistryTypeConfig:
        D = RaftCommand,
        R = (),
        NodeId = u64,
        Node = (),
        Term = u64,
        LeaderId = openraft::impls::leader_id_adv::LeaderId<u64, u64>,
        Vote = openraft::impls::Vote<openraft::impls::leader_id_adv::LeaderId<u64, u64>>,
        SnapshotData = bytes::Bytes,
        AsyncRuntime = openraft::impls::TokioRuntime,
);

type CommittedLeaderIdOfConfig =
    openraft::type_config::alias::CommittedLeaderIdOf<GlobalRegistryTypeConfig>;

pub struct GlobalRegistryStateMachine {
    db: Arc<Mutex<Connection>>,
}

impl Clone for GlobalRegistryStateMachine {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

unsafe impl Send for GlobalRegistryStateMachine {}
unsafe impl Sync for GlobalRegistryStateMachine {}

impl GlobalRegistryStateMachine {
    pub fn new(db_path: PathBuf) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Self::init_schema(&db)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
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
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM state_machine WHERE namespace = ?1 AND key = ?2",
                params![namespace.as_str(), key],
                |row| row.get(0),
            )
            .ok()
    }

    pub fn set(
        &self,
        namespace: &Namespace,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), rusqlite::Error> {
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
        self.db
            .lock()
            .unwrap()
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
        self.db
            .lock()
            .unwrap()
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
        let mut stmt = match db_guard.prepare("SELECT namespace, key, value FROM state_machine") {
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
            Ok(iter) => iter
                .filter_map(|e| e.ok())
                .filter_map(|(ns, k, v)| Namespace::from_str(&ns).map(|n| (n, k, v)))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get_applied_membership(&self) -> Option<StoredMembershipOf<GlobalRegistryTypeConfig>> {
        self.get_membership_raw()
            .and_then(|m| serde_json::from_str(&m).ok())
    }
}

pub struct GlobalRegistryLogStorage {
    db: Arc<Mutex<Connection>>,
}

impl Clone for GlobalRegistryLogStorage {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

unsafe impl Send for GlobalRegistryLogStorage {}
unsafe impl Sync for GlobalRegistryLogStorage {}

impl GlobalRegistryLogStorage {
    pub fn new(db_path: PathBuf) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Self::init_schema(&db)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
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

    pub fn append_log_entry(
        &self,
        index: u64,
        term: u64,
        payload: &[u8],
        membership: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT INTO log_entries (id, term, payload, membership) VALUES (?1, ?2, ?3, ?4)",
            params![index as i64, term as i64, payload, membership],
        )?;
        Ok(())
    }

    pub fn get_log_entry(&self, index: u64) -> Option<(u64, Vec<u8>)> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT term, payload FROM log_entries WHERE id = ?1",
                params![index as i64],
                |row| {
                    let term: i64 = row.get(0)?;
                    let payload: Vec<u8> = row.get(1)?;
                    Ok((term as u64, payload))
                },
            )
            .ok()
    }

    pub fn save_vote_to_storage(&self, vote: &[u8]) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO vote_store (id, vote) VALUES (1, ?1)",
            params![vote],
        )?;
        Ok(())
    }

    pub fn get_vote(&self) -> Option<Vec<u8>> {
        self.db
            .lock()
            .unwrap()
            .query_row("SELECT vote FROM vote_store WHERE id = 1", [], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .ok()
    }

    pub fn get_first_id(&self) -> Option<u64> {
        self.db
            .lock()
            .unwrap()
            .query_row("SELECT MIN(id) FROM log_entries", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    pub fn get_last_id(&self) -> Option<u64> {
        self.db
            .lock()
            .unwrap()
            .query_row("SELECT MAX(id) FROM log_entries", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    pub fn delete_range(&self, start: u64, end: u64) -> Result<(), rusqlite::Error> {
        self.db.lock().unwrap().execute(
            "DELETE FROM log_entries WHERE id >= ?1 AND id < ?2",
            params![start as i64, end as i64],
        )?;
        Ok(())
    }

    pub fn get_all_entries(&self) -> Vec<(u64, u64, Vec<u8>)> {
        let db_guard = self.db.lock().unwrap();
        let mut stmt =
            match db_guard.prepare("SELECT id, term, payload FROM log_entries ORDER BY id") {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };

        let entries = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let term: i64 = row.get(1)?;
            let payload: Vec<u8> = row.get(2)?;
            Ok((id as u64, term as u64, payload))
        });

        match entries {
            Ok(iter) => iter.filter_map(|e| e.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

pub struct GlobalRegistryConfig {
    pub node_id: NodeId,
    pub db_path: PathBuf,
}

impl Clone for GlobalRegistryConfig {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            db_path: self.db_path.clone(),
        }
    }
}

pub struct GlobalRegistry {
    config: GlobalRegistryConfig,
    state_machine: GlobalRegistryStateMachine,
    log_storage: GlobalRegistryLogStorage,
    voting_nodes: std::sync::RwLock<Vec<NodeId>>,
}

impl Clone for GlobalRegistry {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state_machine: self.state_machine.clone(),
            log_storage: self.log_storage.clone(),
            voting_nodes: std::sync::RwLock::new(self.voting_nodes.read().unwrap().clone()),
        }
    }
}

impl GlobalRegistry {
    pub fn new(config: GlobalRegistryConfig) -> Result<Self, rusqlite::Error> {
        let state_machine = GlobalRegistryStateMachine::new(config.db_path.clone())?;
        let log_storage = GlobalRegistryLogStorage::new(config.db_path.join("raft_log.db"))?;
        Ok(Self {
            config,
            state_machine,
            log_storage,
            voting_nodes: std::sync::RwLock::new(Vec::new()),
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

    pub fn set_value(
        &self,
        namespace: &Namespace,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), rusqlite::Error> {
        self.state_machine.set(namespace, key, value)
    }

    pub fn delete_value(&self, namespace: &Namespace, key: &str) -> Result<bool, rusqlite::Error> {
        self.state_machine.delete(namespace, key)
    }
}

pub struct GlobalRegistryLogReader {
    storage: GlobalRegistryLogStorage,
}

impl GlobalRegistryLogReader {
    fn new(storage: GlobalRegistryLogStorage) -> Self {
        Self { storage }
    }
}

impl RaftLogReader<GlobalRegistryTypeConfig> for GlobalRegistryLogReader {
    async fn try_get_log_entries<RB: std::ops::RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> std::io::Result<Vec<EntryOf<GlobalRegistryTypeConfig>>> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(x) => *x,
            std::ops::Bound::Excluded(x) => x + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(x) => x + 1,
            std::ops::Bound::Excluded(x) => *x,
            std::ops::Bound::Unbounded => u64::MAX,
        };

        let entries = self.storage.get_all_entries();
        let mut result = Vec::new();

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);

        for (index, _term, payload) in entries {
            if index >= start && index < end {
                let log_id = openraft::log_id::LogId::new(committed_leader_id.clone(), index);
                let payload_parsed: EntryPayload<RaftCommand, NodeId, ()> =
                    postcard::from_bytes(&payload).unwrap_or(EntryPayload::Blank);
                let entry = EntryOf::<GlobalRegistryTypeConfig>::new(log_id, payload_parsed);
                result.push(entry);
            }
        }

        Ok(result)
    }

    async fn read_vote(&mut self) -> std::io::Result<Option<VoteOf<GlobalRegistryTypeConfig>>> {
        match self.storage.get_vote() {
            Some(v) => {
                let vote: VoteOf<GlobalRegistryTypeConfig> = postcard::from_bytes(&v)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Some(vote))
            }
            None => Ok(None),
        }
    }
}

pub struct GlobalRegistrySnapshotBuilder {
    state_machine: GlobalRegistryStateMachine,
}

impl GlobalRegistrySnapshotBuilder {
    fn new(state_machine: GlobalRegistryStateMachine) -> Self {
        Self { state_machine }
    }
}

impl RaftSnapshotBuilder<GlobalRegistryTypeConfig> for GlobalRegistrySnapshotBuilder {
    async fn build_snapshot(&mut self) -> std::io::Result<SnapshotOf<GlobalRegistryTypeConfig>> {
        let snapshot_data = serde_json::to_vec(&self.state_machine.get_all_entries())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let last_applied = self.state_machine.get_last_applied_log_id().unwrap_or(0);

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);
        let log_id = openraft::log_id::LogId::new(committed_leader_id, last_applied);

        let last_membership = self
            .state_machine
            .get_applied_membership()
            .unwrap_or_else(|| openraft::StoredMembership::default());

        let meta = SnapshotMetaOf::<GlobalRegistryTypeConfig> {
            snapshot_id: format!("snapshot-{}-{}", last_applied, uuid::Uuid::new_v4()),
            last_log_id: Some(log_id),
            last_membership,
        };

        Ok(SnapshotOf::<GlobalRegistryTypeConfig> {
            meta,
            snapshot: Bytes::from(snapshot_data),
        })
    }
}

impl RaftLogStorage<GlobalRegistryTypeConfig> for GlobalRegistryLogStorage {
    type LogReader = GlobalRegistryLogReader;

    async fn get_log_state(&mut self) -> std::io::Result<LogState<GlobalRegistryTypeConfig>> {
        let first_id = self.get_first_id();
        let last_id = self.get_last_id();

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);

        let last_log_id =
            last_id.map(|id| openraft::log_id::LogId::new(committed_leader_id.clone(), id));
        let last_purged_log_id =
            first_id.map(|id| openraft::log_id::LogId::new(committed_leader_id, id));

        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        GlobalRegistryLogReader::new(GlobalRegistryLogStorage {
            db: self.db.clone(),
        })
    }

    async fn save_vote(
        &mut self,
        vote: &<GlobalRegistryTypeConfig as RaftTypeConfig>::Vote,
    ) -> std::io::Result<()> {
        let vote_bytes = postcard::to_stdvec(vote)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        self.save_vote_to_storage(&vote_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        _callback: IOFlushed<GlobalRegistryTypeConfig>,
    ) -> std::io::Result<()>
    where
        I: IntoIterator<Item = EntryOf<GlobalRegistryTypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        for entry in entries {
            let (leader_id, index) = entry.log_id_parts();
            let term = leader_id.term();
            let payload = postcard::to_stdvec(&entry.payload)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            self.append_log_entry(index, term, &payload, None)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
        Ok(())
    }

    async fn truncate_after(
        &mut self,
        last_log_id: Option<LogIdOf<GlobalRegistryTypeConfig>>,
    ) -> std::io::Result<()> {
        match last_log_id {
            Some(id) => {
                let last_id = self.get_last_id().unwrap_or(0);
                self.delete_range(id.index + 1, last_id + 1)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            }
            None => Ok(()),
        }
    }

    async fn purge(&mut self, log_id: LogIdOf<GlobalRegistryTypeConfig>) -> std::io::Result<()> {
        self.delete_range(0, log_id.index + 1)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl RaftStateMachine<GlobalRegistryTypeConfig> for GlobalRegistryStateMachine {
    type SnapshotBuilder = GlobalRegistrySnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> std::io::Result<(
        Option<LogIdOf<GlobalRegistryTypeConfig>>,
        StoredMembershipOf<GlobalRegistryTypeConfig>,
    )> {
        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);

        let last_applied = self
            .get_last_applied_log_id()
            .map(|index| openraft::log_id::LogId::new(committed_leader_id.clone(), index));

        let membership = self
            .get_applied_membership()
            .unwrap_or_else(|| openraft::StoredMembership::default());

        Ok((last_applied, membership))
    }

    async fn apply<Strm>(&mut self, entries: Strm) -> std::io::Result<()>
    where
        Strm: futures::Stream<Item = Result<EntryResponder<GlobalRegistryTypeConfig>, std::io::Error>>
            + Unpin
            + OptionalSend,
    {
        use futures::StreamExt;

        let mut stream = entries;
        while let Some(result) = stream.next().await {
            let (entry, resp) =
                result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let (_leader_id, index) = entry.log_id_parts();

            if let EntryPayload::Normal(data) = &entry.payload {
                match data {
                    RaftCommand::Set {
                        namespace,
                        key,
                        value,
                    } => {
                        self.set(namespace, key, value.clone())
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    }
                    RaftCommand::Delete { namespace, key } => {
                        self.delete(namespace, key)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    }
                }
            }

            self.set_last_applied_log_id(index)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            if let Some(responder) = resp {
                responder.send(());
            }
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        GlobalRegistrySnapshotBuilder::new(GlobalRegistryStateMachine {
            db: self.db.clone(),
        })
    }

    async fn begin_receiving_snapshot(&mut self) -> std::io::Result<Bytes> {
        Ok(Bytes::new())
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<GlobalRegistryTypeConfig>,
        snapshot: Bytes,
    ) -> std::io::Result<()> {
        let entries: Vec<(Namespace, String, Vec<u8>)> = serde_json::from_slice(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM state_machine", [])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        for (namespace, key, value) in entries {
            db.execute(
                "INSERT INTO state_machine (namespace, key, value) VALUES (?1, ?2, ?3)",
                params![namespace.as_str(), key, value],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }

        if let Some(log_id) = meta.last_log_id {
            db.execute(
                "INSERT OR REPLACE INTO snapshot_metadata (key, value) VALUES ('last_applied_log_id', ?1)",
                params![log_id.index.to_string()],
            ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }

        let membership_json = serde_json::to_string(&meta.last_membership)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        db.execute(
            "INSERT OR REPLACE INTO snapshot_metadata (key, value) VALUES ('last_membership', ?1)",
            params![membership_json],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> std::io::Result<Option<SnapshotOf<GlobalRegistryTypeConfig>>> {
        let entries = self.get_all_entries();
        if entries.is_empty() {
            return Ok(None);
        }

        let snapshot_data = serde_json::to_vec(&entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let last_applied = self.get_last_applied_log_id().unwrap_or(0);

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);
        let log_id = openraft::log_id::LogId::new(committed_leader_id, last_applied);

        let last_membership = self
            .get_applied_membership()
            .unwrap_or_else(|| openraft::StoredMembership::default());

        let meta = SnapshotMetaOf::<GlobalRegistryTypeConfig> {
            snapshot_id: format!("snapshot-{}-{}", last_applied, uuid::Uuid::new_v4()),
            last_log_id: Some(log_id),
            last_membership,
        };

        Ok(Some(SnapshotOf::<GlobalRegistryTypeConfig> {
            meta,
            snapshot: Bytes::from(snapshot_data),
        }))
    }
}
