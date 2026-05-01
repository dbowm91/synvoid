use std::fmt::{Debug, Display};
use std::path::{Path, PathBuf};
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use std::io::{Read, Seek, Write};

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

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "org" => Some(Namespace::Org),
            "intel" => Some(Namespace::Intel),
            "revocation" => Some(Namespace::Revocation),
            _ => None,
        }
    }

    pub fn try_from_str(s: &str) -> Option<Self> {
        Self::from_str(s)
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
        source_node_id: Option<String>,
        signature: Option<Vec<u8>>,
    },
    Delete {
        namespace: Namespace,
        key: String,
        source_node_id: Option<String>,
        signature: Option<Vec<u8>>,
    },
}

impl Display for RaftCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaftCommand::Set { namespace, key, .. } => {
                write!(f, "RaftCommand::Set({}, {})", namespace.as_str(), key)
            }
            RaftCommand::Delete { namespace, key, .. } => {
                write!(f, "RaftCommand::Delete({}, {})", namespace.as_str(), key)
            }
        }
    }
}

pub type NodeId = u64;

#[derive(Debug)]
pub enum RaftSnapshotData {
    Memory(std::io::Cursor<Bytes>),
    File(tokio::fs::File),
}

impl RaftSnapshotData {
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self::Memory(std::io::Cursor::new(bytes))
    }

    pub async fn from_file(file: tokio::fs::File) -> Self {
        Self::File(file)
    }

    pub async fn len(&mut self) -> std::io::Result<u64> {
        match self {
            Self::Memory(c) => Ok(c.get_ref().len() as u64),
            Self::File(f) => {
                let meta = f.metadata().await?;
                Ok(meta.len())
            }
        }
    }

    /// Helper to convert to std::io::Read + Seek for synchronous blocking tasks
    pub async fn into_std(self) -> std::io::Result<Box<dyn ReadSeek>> {
        match self {
            Self::Memory(c) => Ok(Box::new(c)),
            Self::File(f) => Ok(Box::new(f.into_std().await)),
        }
    }
}

pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

impl AsyncRead for RaftSnapshotData {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Memory(c) => std::pin::Pin::new(c).poll_read(cx, buf),
            Self::File(f) => std::pin::Pin::new(f).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RaftSnapshotData {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Memory(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Memory snapshot data is read-only",
            ))),
            Self::File(f) => std::pin::Pin::new(f).poll_write(_cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Memory(_) => std::task::Poll::Ready(Ok(())),
            Self::File(f) => std::pin::Pin::new(f).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Memory(_) => std::task::Poll::Ready(Ok(())),
            Self::File(f) => std::pin::Pin::new(f).poll_shutdown(cx),
        }
    }
}

impl AsyncSeek for RaftSnapshotData {
    fn start_seek(
        self: std::pin::Pin<&mut Self>,
        position: std::io::SeekFrom,
    ) -> std::io::Result<()> {
        match self.get_mut() {
            Self::Memory(c) => std::pin::Pin::new(c).start_seek(position),
            Self::File(f) => std::pin::Pin::new(f).start_seek(position),
        }
    }

    fn poll_complete(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        match self.get_mut() {
            Self::Memory(c) => std::pin::Pin::new(c).poll_complete(cx),
            Self::File(f) => std::pin::Pin::new(f).poll_complete(cx),
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
        SnapshotData = RaftSnapshotData,
        AsyncRuntime = openraft::impls::TokioRuntime,
);

type CommittedLeaderIdOfConfig =
    openraft::type_config::alias::CommittedLeaderIdOf<GlobalRegistryTypeConfig>;

const STREAMING_SNAPSHOT_MAGIC: u32 = 0x53524D53;

#[derive(serde::Serialize, serde::Deserialize)]
struct StreamingSnapshotEntry {
    ns: String,
    key: String,
    val: Vec<u8>,
}

pub struct GlobalRegistryStateMachine {
    pub(crate) db: Arc<Mutex<Connection>>,
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
        Self::new_with_connection(db)
    }

    pub fn new_with_connection(db: Connection) -> Result<Self, rusqlite::Error> {
        Self::init_schema(&db)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn db(&self) -> Arc<Mutex<Connection>> {
        self.db.clone()
    }

    pub fn init_schema(db: &Connection) -> Result<(), rusqlite::Error> {
        let _ = db.execute("PRAGMA journal_mode=WAL", []);
        let _ = db.execute("PRAGMA busy_timeout=5000", []);
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
            .and_then(|s| s.split(':').next_back()?.parse().ok())
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

    pub async fn streaming_serialize(&self) -> std::io::Result<RaftSnapshotData> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let mut file = tempfile::tempfile()?;

            let db_guard = db.lock().unwrap();
            let mut stmt = db_guard
                .prepare("SELECT namespace, key, value FROM state_machine")
                .map_err(std::io::Error::other)?;

            let entry_count: u64 = db_guard
                .query_row("SELECT COUNT(*) FROM state_machine", [], |row| row.get(0))
                .map_err(std::io::Error::other)?;

            file.write_all(&STREAMING_SNAPSHOT_MAGIC.to_le_bytes())?;
            file.write_all(&entry_count.to_le_bytes())?;

            let rows = stmt
                .query_map([], |row| {
                    let ns: String = row.get(0)?;
                    let key: String = row.get(1)?;
                    let val: Vec<u8> = row.get(2)?;
                    Ok((ns, key, val))
                })
                .map_err(std::io::Error::other)?;

            for row_result in rows {
                let (ns, key, val) = row_result.map_err(std::io::Error::other)?;
                let entry = StreamingSnapshotEntry { ns, key, val };
                let entry_bytes = postcard::to_stdvec(&entry).map_err(std::io::Error::other)?;
                let len = entry_bytes.len() as u32;
                file.write_all(&len.to_le_bytes())?;
                file.write_all(&entry_bytes)?;
            }

            file.flush()?;
            file.seek(std::io::SeekFrom::Start(0))?;

            Ok(RaftSnapshotData::File(tokio::fs::File::from_std(file)))
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    }

    pub async fn streaming_deserialize_and_apply(
        &self,
        data: RaftSnapshotData,
    ) -> std::io::Result<()> {
        let db = self.db.clone();
        let std_data = data.into_std().await?;

        tokio::task::spawn_blocking(move || {
            let mut data = std_data;
            let mut magic_buf = [0u8; 4];
            if data.read_exact(&mut magic_buf).is_err() {
                return Self::fallback_json_install_from_reader(db, data);
            }

            let magic = u32::from_le_bytes(magic_buf);
            if magic != STREAMING_SNAPSHOT_MAGIC {
                data.seek(std::io::SeekFrom::Start(0))?;
                return Self::fallback_json_install_from_reader(db, data);
            }

            let mut count_buf = [0u8; 8];
            data.read_exact(&mut count_buf)?;
            let entry_count = u64::from_le_bytes(count_buf);

            let db_guard = db.lock().unwrap();
            db_guard
                .execute("DELETE FROM state_machine", [])
                .map_err(std::io::Error::other)?;

            for _ in 0..entry_count {
                let mut len_buf = [0u8; 4];
                data.read_exact(&mut len_buf)?;
                let entry_len = u32::from_le_bytes(len_buf) as usize;

                let mut entry_buf = vec![0u8; entry_len];
                data.read_exact(&mut entry_buf)?;

                let entry: StreamingSnapshotEntry = postcard::from_bytes(&entry_buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                db_guard
                    .execute(
                        "INSERT INTO state_machine (namespace, key, value) VALUES (?1, ?2, ?3)",
                        rusqlite::params![entry.ns, entry.key, entry.val],
                    )
                    .map_err(std::io::Error::other)?;
            }

            Ok(())
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    }

    fn fallback_json_install_from_reader(
        db: Arc<Mutex<Connection>>,
        mut reader: Box<dyn ReadSeek>,
    ) -> std::io::Result<()> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Self::fallback_json_install_static(db, &buf)
    }

    fn fallback_json_install_static(
        db: Arc<Mutex<Connection>>,
        data: &[u8],
    ) -> std::io::Result<()> {
        let entries: Vec<(Namespace, String, Vec<u8>)> = serde_json::from_slice(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let db_guard = db.lock().unwrap();
        db_guard
            .execute("DELETE FROM state_machine", [])
            .map_err(std::io::Error::other)?;

        for (ns, key, val) in entries {
            db_guard
                .execute(
                    "INSERT INTO state_machine (namespace, key, value) VALUES (?1, ?2, ?3)",
                    rusqlite::params![ns.as_str(), key, val],
                )
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    }

    fn fallback_json_install(&self, data: &[u8]) -> std::io::Result<()> {
        Self::fallback_json_install_static(self.db.clone(), data)
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
        let _ = db.execute("PRAGMA journal_mode=WAL", []);
        let _ = db.execute("PRAGMA busy_timeout=5000", []);
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
            "CREATE INDEX IF NOT EXISTS idx_log_entries_id_term ON log_entries(id, term)",
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

    pub fn get_log_entries_paged(&self, start: u64, limit: u64) -> Vec<(u64, u64, Vec<u8>)> {
        let db_guard = self.db.lock().unwrap();
        let mut stmt = match db_guard.prepare(
            "SELECT id, term, payload FROM log_entries WHERE id >= ?1 ORDER BY id LIMIT ?2",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![start as i64, limit as i64], |row| {
            let id: i64 = row.get(0)?;
            let term: i64 = row.get(1)?;
            let payload: Vec<u8> = row.get(2)?;
            Ok((id as u64, term as u64, payload))
        });
        match rows {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
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

    pub fn state_machine(&self) -> &GlobalRegistryStateMachine {
        &self.state_machine
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

        let limit = end.saturating_sub(start);
        let entries = self.storage.get_log_entries_paged(start, limit);
        let mut result = Vec::new();

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);

        for (index, _term, payload) in entries {
            if index >= start && index < end {
                let log_id = openraft::log_id::LogId::new(committed_leader_id, index);
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
        let snapshot_data = self.state_machine.streaming_serialize().await?;

        let last_applied = self.state_machine.get_last_applied_log_id().unwrap_or(0);

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);
        let log_id = openraft::log_id::LogId::new(committed_leader_id, last_applied);

        let last_membership = self
            .state_machine
            .get_applied_membership()
            .unwrap_or_else(openraft::StoredMembership::default);

        let meta = SnapshotMetaOf::<GlobalRegistryTypeConfig> {
            snapshot_id: format!("snapshot-{}-{}", last_applied, uuid::Uuid::new_v4()),
            last_log_id: Some(log_id),
            last_membership,
        };

        Ok(SnapshotOf::<GlobalRegistryTypeConfig> {
            meta,
            snapshot: snapshot_data,
        })
    }
}

impl RaftLogStorage<GlobalRegistryTypeConfig> for GlobalRegistryLogStorage {
    type LogReader = GlobalRegistryLogReader;

    async fn get_log_state(&mut self) -> std::io::Result<LogState<GlobalRegistryTypeConfig>> {
        let first_id = self.get_first_id();
        let last_id = self.get_last_id();

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);

        let last_log_id = last_id.map(|id| openraft::log_id::LogId::new(committed_leader_id, id));
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
        let vote_bytes = postcard::to_stdvec(vote).map_err(std::io::Error::other)?;
        self.save_vote_to_storage(&vote_bytes)
            .map_err(std::io::Error::other)
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
            let payload = postcard::to_stdvec(&entry.payload).map_err(std::io::Error::other)?;
            self.append_log_entry(index, term, &payload, None)
                .map_err(std::io::Error::other)?;
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
                    .map_err(std::io::Error::other)
            }
            None => Ok(()),
        }
    }

    async fn purge(&mut self, log_id: LogIdOf<GlobalRegistryTypeConfig>) -> std::io::Result<()> {
        self.delete_range(0, log_id.index + 1)
            .map_err(std::io::Error::other)
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
            .map(|index| openraft::log_id::LogId::new(committed_leader_id, index));

        let membership = self
            .get_applied_membership()
            .unwrap_or_else(openraft::StoredMembership::default);

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
            let (entry, resp) = result.map_err(std::io::Error::other)?;
            let (_leader_id, index) = entry.log_id_parts();

            if let EntryPayload::Normal(data) = &entry.payload {
                match data {
                    RaftCommand::Set {
                        namespace,
                        key,
                        value,
                        source_node_id: _,
                        signature: _,
                    } => {
                        self.set(namespace, key, value.clone())
                            .map_err(std::io::Error::other)?;
                    }
                    RaftCommand::Delete {
                        namespace,
                        key,
                        source_node_id: _,
                        signature: _,
                    } => {
                        self.delete(namespace, key).map_err(std::io::Error::other)?;
                    }
                }
            }

            self.set_last_applied_log_id(index)
                .map_err(std::io::Error::other)?;

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

    async fn begin_receiving_snapshot(&mut self) -> std::io::Result<RaftSnapshotData> {
        let std_file = tokio::task::spawn_blocking(|| tempfile::tempfile()).await??;
        let file = tokio::fs::File::from_std(std_file);
        Ok(RaftSnapshotData::File(file))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<GlobalRegistryTypeConfig>,
        snapshot: RaftSnapshotData,
    ) -> std::io::Result<()> {
        self.streaming_deserialize_and_apply(snapshot).await?;

        let db = self.db.lock().unwrap();

        if let Some(log_id) = meta.last_log_id {
            db.execute(
                "INSERT OR REPLACE INTO snapshot_metadata (key, value) VALUES ('last_applied_log_id', ?1)",
                params![log_id.index.to_string()],
            ).map_err(std::io::Error::other)?;
        }

        let membership_json =
            serde_json::to_string(&meta.last_membership).map_err(std::io::Error::other)?;
        db.execute(
            "INSERT OR REPLACE INTO snapshot_metadata (key, value) VALUES ('last_membership', ?1)",
            params![membership_json],
        )
        .map_err(std::io::Error::other)?;

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> std::io::Result<Option<SnapshotOf<GlobalRegistryTypeConfig>>> {
        let count: u64 = {
            let db_guard = self.db.lock().unwrap();
            db_guard
                .query_row("SELECT COUNT(*) FROM state_machine", [], |row| row.get(0))
                .map_err(std::io::Error::other)?
        };

        if count == 0 {
            return Ok(None);
        }

        let snapshot_data = self.streaming_serialize().await?;

        let last_applied = self.get_last_applied_log_id().unwrap_or(0);

        let committed_leader_id = CommittedLeaderIdOfConfig::new(0, 0);
        let log_id = openraft::log_id::LogId::new(committed_leader_id, last_applied);

        let last_membership = self
            .get_applied_membership()
            .unwrap_or_else(openraft::StoredMembership::default);

        let meta = SnapshotMetaOf::<GlobalRegistryTypeConfig> {
            snapshot_id: format!("snapshot-{}-{}", last_applied, uuid::Uuid::new_v4()),
            last_log_id: Some(log_id),
            last_membership,
        };

        Ok(Some(SnapshotOf::<GlobalRegistryTypeConfig> {
            meta,
            snapshot: snapshot_data,
        }))
    }
}
