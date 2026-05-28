use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Uri};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use utoipa::ToSchema;

use crate::config::site::FastCgiConfig;
use crate::fastcgi::streaming::FastCgiResponseStream;
use crate::fastcgi::{FastCgiClient, FastCgiError, FastCgiResponse};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FastCgiPoolStatus {
    pub socket: String,
    pub max_connections: usize,
    pub active_connections: usize,
    pub available_connections: usize,
    pub in_use_connections: usize,
    pub is_healthy: bool,
    pub is_closed: bool,
    pub is_draining: bool,
    pub connection_timeout_ms: u64,
    pub health_check_interval_secs: u64,
    pub max_idle_time_secs: u64,
}

#[derive(Debug, Clone)]
pub struct FastCgiPoolConfig {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
    pub max_idle_time: Duration,
    pub socket: String,
}

impl Default for FastCgiPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            connection_timeout: Duration::from_secs(5),
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(3),
            max_idle_time: Duration::from_secs(300),
            socket: String::new(),
        }
    }
}

struct PooledConnection {
    client: FastCgiClient,
    last_used: Instant,
    in_use: bool,
}

pub struct FastCgiPool {
    config: FastCgiPoolConfig,
    connections: RwLock<VecDeque<PooledConnection>>,
    semaphore: tokio::sync::Semaphore,
    health_check_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
    closed: RwLock<bool>,
    draining: RwLock<bool>,
}

impl FastCgiPool {
    pub fn new(config: FastCgiPoolConfig) -> Arc<Self> {
        let max_connections = config.max_connections;
        let health_check_interval = config.health_check_interval;

        let pool = Arc::new(Self {
            config,
            connections: RwLock::new(VecDeque::new()),
            semaphore: tokio::sync::Semaphore::new(max_connections),
            health_check_task: RwLock::new(None),
            closed: RwLock::new(false),
            draining: RwLock::new(false),
        });

        Self::start_health_check(Arc::clone(&pool), health_check_interval);
        pool
    }

    pub fn from_config(fcgi_config: &FastCgiConfig, socket: String) -> Arc<Self> {
        let config = FastCgiPoolConfig {
            max_connections: fcgi_config.max_connections.unwrap_or(10),
            connection_timeout: Duration::from_secs(fcgi_config.connect_timeout.unwrap_or(5)),
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(3),
            max_idle_time: Duration::from_secs(300),
            socket,
        };

        Self::new(config)
    }

    pub fn start_drain(&self) {
        *self.draining.write() = true;
        tracing::info!(
            "FastCGI pool for {} entering drain mode",
            self.config.socket
        );
    }

    pub fn is_draining(&self) -> bool {
        *self.draining.read()
    }

    pub fn finish_drain(&self) {
        *self.draining.write() = false;
        tracing::info!("FastCGI pool for {} drain complete", self.config.socket);
    }

    pub async fn drain_with_timeout(&self, timeout: Duration) -> Result<(), String> {
        self.start_drain();

        let start = std::time::Instant::now();
        loop {
            let active = self.connection_count();
            let in_use = self.status().in_use_connections;

            if in_use == 0 || start.elapsed() >= timeout {
                break;
            }

            tracing::debug!(
                "PHP-FPM pool drain in progress for {}: {} active, {} in use",
                self.config.socket,
                active,
                in_use
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        self.finish_drain();

        tracing::info!(
            "PHP-FPM pool drain completed for {} (was draining for {:?})",
            self.config.socket,
            start.elapsed()
        );

        Ok(())
    }

    fn start_health_check(pool: Arc<Self>, interval: Duration) {
        let task_pool = Arc::clone(&pool);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                task_pool.check_connections();
            }
        });

        *pool.health_check_task.write() = Some(handle);
    }

    fn check_connections(&self) {
        let mut connections = self.connections.write();
        let now = Instant::now();
        let max_idle = self.config.max_idle_time;

        connections.retain(|conn| {
            if conn.in_use {
                return true;
            }
            if now.duration_since(conn.last_used) > max_idle {
                tracing::debug!("Removing idle FastCGI connection");
                return false;
            }
            true
        });
    }

    pub async fn execute(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponse, FastCgiError> {
        if *self.closed.read() {
            return Err(FastCgiError::ConnectionFailed("Pool is closed".to_string()));
        }

        let permit = timeout(self.config.connection_timeout, self.semaphore.acquire())
            .await
            .map_err(|_| FastCgiError::ConnectionFailed("Timeout acquiring permit".to_string()))?
            .map_err(|_| FastCgiError::ConnectionFailed("Semaphore closed".to_string()))?;

        let _permit = permit;

        let connection = self.get_connection().await?;

        let result = connection
            .client
            .execute(method, uri, headers, body, config)
            .await;

        self.release_connection(connection);

        result
    }

    pub async fn execute_stream(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponseStream, FastCgiError> {
        use crate::fastcgi::streaming::StreamingFastCgiClient;

        if *self.closed.read() {
            return Err(FastCgiError::ConnectionFailed("Pool is closed".to_string()));
        }

        let _permit = timeout(self.config.connection_timeout, self.semaphore.acquire())
            .await
            .map_err(|_| FastCgiError::ConnectionFailed("Timeout acquiring permit".to_string()))?
            .map_err(|_| FastCgiError::ConnectionFailed("Semaphore closed".to_string()))?;

        let client = StreamingFastCgiClient::new(self.config.socket.clone());
        let params = client.build_params_from_request(method, uri, headers, config);

        let body_vec = body.to_vec();
        let body_cursor = std::io::Cursor::new(body_vec);

        client.execute_stream(params, body_cursor, config).await
    }

    async fn get_connection(&self) -> Result<PooledConnection, FastCgiError> {
        let socket = self.config.socket.clone();

        {
            let mut connections = self.connections.write();

            if let Some(mut conn) = connections.pop_front() {
                if !conn.in_use {
                    conn.in_use = true;
                    return Ok(conn);
                }
            }
        }

        let client = FastCgiClient::new(socket);
        Ok(PooledConnection {
            client,
            last_used: Instant::now(),
            in_use: true,
        })
    }

    fn release_connection(&self, mut connection: PooledConnection) {
        connection.in_use = false;
        connection.last_used = Instant::now();

        let mut connections = self.connections.write();
        if connections.len() < self.config.max_connections {
            connections.push_back(connection);
        }
    }

    pub fn close(&self) {
        *self.closed.write() = true;

        if let Some(handle) = self.health_check_task.write().take() {
            handle.abort();
        }

        self.connections.write().clear();
        self.semaphore.close();
    }

    pub fn health_check(&self) -> bool {
        if *self.closed.read() {
            return false;
        }

        let socket = &self.config.socket;
        let timeout_duration = self.config.health_check_timeout;

        let (addr, is_tcp) = match crate::fastcgi::parse_socket_address(socket) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };

        if is_tcp {
            use std::net::TcpStream;
            use std::time::Instant;

            let start = Instant::now();
            let stream = TcpStream::connect(&addr);
            match stream {
                Ok(s) => {
                    s.set_read_timeout(Some(timeout_duration.saturating_sub(start.elapsed())))
                        .ok();
                    true
                }
                Err(_) => false,
            }
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::net::UnixStream;
                use std::time::Instant;

                let start = Instant::now();
                let stream = UnixStream::connect(&addr);
                match stream {
                    Ok(s) => {
                        s.set_read_timeout(Some(timeout_duration.saturating_sub(start.elapsed())))
                            .ok();
                        true
                    }
                    Err(_) => false,
                }
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    pub fn available_connections(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub fn status(&self) -> FastCgiPoolStatus {
        let connections = self.connections.read();
        let in_use = connections.iter().filter(|c| c.in_use).count();
        let active = connections.len();

        FastCgiPoolStatus {
            socket: self.config.socket.clone(),
            max_connections: self.config.max_connections,
            active_connections: active,
            available_connections: self.semaphore.available_permits(),
            in_use_connections: in_use,
            is_healthy: self.health_check(),
            is_closed: *self.closed.read(),
            is_draining: *self.draining.read(),
            connection_timeout_ms: self.config.connection_timeout.as_millis() as u64,
            health_check_interval_secs: self.config.health_check_interval.as_secs() as u64,
            max_idle_time_secs: self.config.max_idle_time.as_secs() as u64,
        }
    }
}

impl Drop for FastCgiPool {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct FastCgiPoolManager {
    pools: RwLock<HashMap<String, Arc<FastCgiPool>>>,
}

type HashMap<K, V> = std::collections::HashMap<K, V>;

impl FastCgiPoolManager {
    pub fn new() -> Self {
        Self {
            pools: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_create_pool(&self, socket: &str, config: &FastCgiConfig) -> Arc<FastCgiPool> {
        let key = socket.to_string();

        if let Some(pool) = self.pools.read().get(&key) {
            return Arc::clone(pool);
        }

        let pool = FastCgiPool::from_config(config, socket.to_string());

        let existing = self.pools.write().insert(key, Arc::clone(&pool));
        if existing.is_some() {
            pool.close();
        }

        Arc::clone(&pool)
    }

    pub fn remove_pool(&self, socket: &str) {
        if let Some(pool) = self.pools.write().remove(&socket.to_string()) {
            pool.close();
        }
    }

    pub fn get_pool(&self, socket: &str) -> Option<Arc<FastCgiPool>> {
        self.pools.read().get(socket).cloned()
    }

    pub fn close_all(&self) {
        let pools: Vec<_> = self.pools.write().drain().collect();
        for (_, pool) in pools {
            pool.close();
        }
    }

    pub fn get_all_pool_statuses(&self) -> Vec<FastCgiPoolStatus> {
        let pools = self.pools.read();
        pools.values().map(|p| p.status()).collect()
    }

    pub async fn drain_and_reload_pool(
        &self,
        socket: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let pool = self
            .pools
            .read()
            .get(socket)
            .cloned()
            .ok_or_else(|| format!("Pool not found for socket: {}", socket))?;

        pool.drain_with_timeout(timeout).await
    }
}

impl Default for FastCgiPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = FastCgiPoolConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.connection_timeout, Duration::from_secs(5));
        assert_eq!(config.max_idle_time, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let config = FastCgiPoolConfig {
            socket: "/tmp/test.sock".to_string(),
            ..Default::default()
        };
        let pool = FastCgiPool::new(config);
        assert!(pool.health_check());
        pool.close();
    }

    #[tokio::test]
    async fn test_pool_manager() {
        let manager = FastCgiPoolManager::new();
        let config = crate::config::site::FastCgiConfig::default();

        let pool1 = manager.get_or_create_pool("/tmp/test.sock", &config);
        let pool2 = manager.get_or_create_pool("/tmp/test.sock", &config);

        assert!(Arc::ptr_eq(&pool1, &pool2));

        manager.close_all();
    }
}
