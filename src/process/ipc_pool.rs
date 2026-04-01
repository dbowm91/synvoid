use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct IpcConnectionPool {
    inner: Arc<IpcConnectionPoolInner>,
}

struct IpcConnectionPoolInner {
    config: PoolConfig,
    endpoint_stats: RwLock<HashMap<String, EndpointStats>>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct PoolConfig {
    max_connections_per_endpoint: usize,
    connection_ttl: Duration,
}

#[derive(Clone, Default)]
struct EndpointStats {
    active_connections: Arc<AtomicUsize>,
    total_connections: Arc<AtomicU64>,
    failed_connections: Arc<AtomicU64>,
    last_connection_time: Option<Instant>,
}

impl IpcConnectionPool {
    pub fn new(max_connections_per_endpoint: usize, connection_ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(IpcConnectionPoolInner {
                config: PoolConfig {
                    max_connections_per_endpoint,
                    connection_ttl: Duration::from_secs(connection_ttl_secs),
                },
                endpoint_stats: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub async fn try_acquire(&self, endpoint_name: &str) -> Result<ConnectionPermit, PoolError> {
        let mut stats = self.inner.endpoint_stats.write().await;

        let endpoint_stats =
            stats
                .entry(endpoint_name.to_string())
                .or_insert_with(|| EndpointStats {
                    active_connections: Arc::new(AtomicUsize::new(0)),
                    total_connections: Arc::new(AtomicU64::new(0)),
                    failed_connections: Arc::new(AtomicU64::new(0)),
                    last_connection_time: None,
                });

        let current = endpoint_stats.active_connections.load(Ordering::Acquire);
        if current >= self.inner.config.max_connections_per_endpoint {
            return Err(PoolError::TooManyConnections {
                endpoint: endpoint_name.to_string(),
                limit: self.inner.config.max_connections_per_endpoint,
            });
        }

        endpoint_stats
            .active_connections
            .fetch_add(1, Ordering::AcqRel);
        endpoint_stats
            .total_connections
            .fetch_add(1, Ordering::AcqRel);
        endpoint_stats.last_connection_time = Some(Instant::now());

        Ok(ConnectionPermit {
            endpoint_name: endpoint_name.to_string(),
            active_counter: endpoint_stats.active_connections.clone(),
            total_counter: endpoint_stats.total_connections.clone(),
            acquired_at: Instant::now(),
        })
    }

    pub async fn release(&self, endpoint_name: &str) {
        let stats = self.inner.endpoint_stats.read().await;

        if let Some(endpoint_stats) = stats.get(endpoint_name) {
            endpoint_stats
                .active_connections
                .fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub async fn record_failure(&self, endpoint_name: &str) {
        let stats = self.inner.endpoint_stats.read().await;

        if let Some(endpoint_stats) = stats.get(endpoint_name) {
            endpoint_stats
                .failed_connections
                .fetch_add(1, Ordering::AcqRel);
            endpoint_stats
                .active_connections
                .fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub async fn get_stats(&self, endpoint_name: &str) -> Option<ConnectionPoolStats> {
        let stats = self.inner.endpoint_stats.read().await;

        stats.get(endpoint_name).map(|s| ConnectionPoolStats {
            active_connections: s.active_connections.load(Ordering::Acquire),
            total_connections: s.total_connections.load(Ordering::Acquire),
            failed_connections: s.failed_connections.load(Ordering::Acquire),
        })
    }
}

pub struct ConnectionPermit {
    #[allow(dead_code)]
    endpoint_name: String,
    active_counter: Arc<AtomicUsize>,
    #[allow(dead_code)]
    total_counter: Arc<AtomicU64>,
    #[allow(dead_code)]
    acquired_at: Instant,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let _ = self
            .active_counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1));
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionPoolStats {
    pub active_connections: usize,
    pub total_connections: u64,
    pub failed_connections: u64,
}

#[derive(Debug)]
pub enum PoolError {
    TooManyConnections { endpoint: String, limit: usize },
    ConnectionFailed(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::TooManyConnections { endpoint, limit } => {
                write!(f, "Too many connections to {}: limit {}", endpoint, limit)
            }
            PoolError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
        }
    }
}

impl std::error::Error for PoolError {}

pub mod config {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IpcConnectionPoolConfig {
        #[serde(default = "default_max_connections_per_endpoint")]
        pub max_connections_per_endpoint: usize,
        #[serde(default = "default_connection_ttl_secs")]
        pub connection_ttl_secs: u64,
    }

    fn default_max_connections_per_endpoint() -> usize {
        20
    }
    fn default_connection_ttl_secs() -> u64 {
        300
    }

    impl Default for IpcConnectionPoolConfig {
        fn default() -> Self {
            Self {
                max_connections_per_endpoint: default_max_connections_per_endpoint(),
                connection_ttl_secs: default_connection_ttl_secs(),
            }
        }
    }
}
