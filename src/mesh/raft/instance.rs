use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openraft::Raft;
use tokio::sync::broadcast;

use crate::mesh::backend::MeshBackendPool;
use crate::mesh::raft::network::MeshRaftNetworkFactory;
use crate::mesh::raft::state_machine::{
    GlobalRegistry, GlobalRegistryConfig, GlobalRegistryLogStorage, GlobalRegistryStateMachine,
    GlobalRegistryTypeConfig, Namespace, RaftCommand,
};
use crate::mesh::MeshProxy;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaftInitConfig {
    pub node_id: u64,
    pub db_path: PathBuf,
    pub cluster_nodes: Vec<u64>,
    #[serde(default)]
    pub is_observer: bool,
    #[serde(default)]
    pub observer_tags: Vec<String>,
}

pub struct RaftInstance {
    pub raft: Arc<Raft<GlobalRegistryTypeConfig, GlobalRegistryStateMachine>>,
    pub registry: GlobalRegistry,
    pub network_factory: MeshRaftNetworkFactory,
    node_id: u64,
    is_observer: bool,
    observer_tags: Vec<String>,
    shutdown_tx: Arc<tokio::sync::RwLock<Option<broadcast::Sender<()>>>>,
}

impl RaftInstance {
    pub async fn new(
        node_id: u64,
        db_path: PathBuf,
        backend_pool: Arc<MeshBackendPool>,
        proxy: Arc<MeshProxy>,
        is_observer: bool,
        observer_tags: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = GlobalRegistryConfig {
            node_id,
            db_path: db_path.clone(),
        };

        let state_machine = GlobalRegistryStateMachine::new(db_path.clone())?;
        let log_storage = GlobalRegistryLogStorage::new(db_path.join("raft_log.db"))?;

        let registry = GlobalRegistry::new(config)?;

        let network_factory = MeshRaftNetworkFactory::new(backend_pool, proxy);

        let raft = Raft::new(
            node_id,
            Arc::new(openraft::Config::default()),
            network_factory.clone(),
            log_storage,
            state_machine,
        )
        .await?;

        Ok(Self {
            raft: Arc::new(raft),
            registry,
            network_factory,
            node_id,
            is_observer,
            observer_tags,
            shutdown_tx: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    pub async fn initialize(
        &self,
        cluster_nodes: Vec<u64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if cluster_nodes.is_empty() {
            return Err("Cannot initialize Raft cluster with no nodes".into());
        }

        let nodes: BTreeSet<u64> = cluster_nodes.iter().cloned().collect();
        self.raft.initialize(nodes).await?;

        tracing::info!(
            "Raft instance {} initialized with cluster nodes: {:?}",
            self.node_id,
            cluster_nodes
        );
        Ok(())
    }

    pub async fn add_learner(
        &self,
        node_id: u64,
        tags: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            "Adding learner node {} with tags {:?} to cluster",
            node_id,
            tags
        );

        let node = ();
        self.raft
            .add_learner(node_id, node, false)
            .await
            .map_err(|e| format!("Failed to add learner: {}", e))?;

        tracing::info!("Learner node {} added successfully", node_id);
        Ok(())
    }

    pub async fn add_node(
        &self,
        node_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Node added to cluster (cluster management via external coordination)");
        Ok(())
    }

    pub async fn remove_node(
        &self,
        _node_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Node removed from cluster (cluster management via external coordination)");
        Ok(())
    }

    pub async fn client_write(
        &self,
        command: RaftCommand,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.raft.client_write(command).await?;
        Ok(resp.log_id.index)
    }

    pub async fn read(&self, namespace: Namespace, key: &str) -> Option<Vec<u8>> {
        self.registry.get_value(&namespace, key)
    }

    pub async fn is_leader(&self) -> bool {
        self.raft.is_leader()
    }

    pub async fn get_leader_id(&self) -> Option<u64> {
        if self.is_leader().await {
            Some(self.node_id)
        } else {
            None
        }
    }

    pub async fn wait_for_leader(
        &self,
        timeout: Duration,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err("Timeout waiting for leader".into());
            }
            if let Some(leader) = self.get_leader_id().await {
                return Ok(leader);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tx = self.shutdown_tx.read().await;
        if let Some(sender) = tx.as_ref() {
            let _ = sender.send(());
        }
        self.raft.shutdown().await?;
        tracing::info!("Raft instance {} shutdown", self.node_id);
        Ok(())
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    pub fn registry(&self) -> &GlobalRegistry {
        &self.registry
    }

    pub fn is_observer(&self) -> bool {
        self.is_observer
    }

    pub fn observer_tags(&self) -> &[String] {
        &self.observer_tags
    }
}

impl Clone for RaftInstance {
    fn clone(&self) -> Self {
        Self {
            raft: self.raft.clone(),
            registry: self.registry.clone(),
            network_factory: self.network_factory.clone(),
            node_id: self.node_id,
            is_observer: self.is_observer,
            observer_tags: self.observer_tags.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }
}

unsafe impl Send for RaftInstance {}
unsafe impl Sync for RaftInstance {}

pub struct RaftSnapshotManager {
    db_path: PathBuf,
}

impl RaftSnapshotManager {
    pub fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    pub fn create_point_in_time_snapshot(
        &self,
        target_path: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let source = rusqlite::Connection::open(&self.db_path)?;
        let mut target = rusqlite::Connection::open(target_path)?;

        let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
        backup.run_to_completion(5, Duration::from_millis(250), None)?;

        tracing::info!("Created point-in-time snapshot at {:?}", target_path);
        Ok(())
    }

    pub fn restore_from_snapshot(
        snapshot_path: &PathBuf,
        db_path: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let snapshot = rusqlite::Connection::open(snapshot_path)?;
        let mut target = rusqlite::Connection::open(db_path)?;

        let backup = rusqlite::backup::Backup::new(&snapshot, &mut target)?;
        backup.run_to_completion(5, Duration::from_millis(250), None)?;

        tracing::info!("Restored database from snapshot at {:?}", snapshot_path);
        Ok(())
    }

    pub fn compact_database(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        conn.execute_batch("VACUUM")?;
        tracing::info!("Compacted database at {:?}", self.db_path);
        Ok(())
    }

    pub fn get_snapshot_path(&self, snapshot_id: &str) -> PathBuf {
        self.db_path
            .parent()
            .unwrap()
            .join(format!("snapshot_{}.db", snapshot_id))
    }
}
