use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use parking_lot::RwLock;

use crate::config::ConnectionLimitsConfig;

pub struct ConnectionLimiter {
    config: ConnectionLimitsConfig,
    total_connections: AtomicU32,
    connection_queue: RwLock<Vec<mpsc::Sender<ConnectionToken>>>,
    ip_connections: DashMap<IpAddr, AtomicU32>,
    ip_burst_tokens: DashMap<IpAddr, AtomicU32>,
    site_connections: DashMap<String, DashMap<IpAddr, AtomicU32>>,
    site_total_connections: DashMap<String, AtomicU32>,
}

#[derive(Debug)]
pub struct ConnectionToken {
    pub site_id: String,
    pub client_ip: IpAddr,
    pub acquired_at: Instant,
}

impl ConnectionLimiter {
    pub fn new(config: ConnectionLimitsConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            total_connections: AtomicU32::new(0),
            connection_queue: RwLock::new(Vec::new()),
            ip_connections: DashMap::new(),
            ip_burst_tokens: DashMap::new(),
            site_connections: DashMap::new(),
            site_total_connections: DashMap::new(),
        })
    }

    pub async fn try_acquire(
        &self,
        site_id: &str,
        client_ip: IpAddr,
    ) -> Result<ConnectionToken, ConnectionLimitError> {
        self.try_acquire_with_limits(site_id, client_ip, None, None)
            .await
    }

    pub async fn try_acquire_with_limits(
        &self,
        site_id: &str,
        client_ip: IpAddr,
        max_per_site: Option<u32>,
        max_per_ip: Option<u32>,
    ) -> Result<ConnectionToken, ConnectionLimitError> {
        let config = &self.config;

        let total = self.total_connections.load(Ordering::Acquire);
        if total >= config.max_connections {
            return Err(ConnectionLimitError::GlobalLimitExceeded);
        }

        let effective_max_per_site = max_per_site.unwrap_or(10000);
        let site_count = if max_per_site.is_some() {
            self.site_total_connections
                .get(site_id)
                .map(|c| c.load(Ordering::Acquire))
                .unwrap_or(0)
        } else {
            0
        };

        if site_count >= effective_max_per_site {
            return Err(ConnectionLimitError::SiteLimitExceeded);
        }

        let effective_max_per_ip = max_per_ip.unwrap_or(config.max_connections_per_ip);
        let ip_count = self.ip_connections
            .get(&client_ip)
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0);

        if ip_count >= effective_max_per_ip {
            return Err(ConnectionLimitError::PerIpLimitExceeded);
        }

        let can_burst = self.ip_burst_tokens
            .get(&client_ip)
            .map(|t| t.load(Ordering::Acquire))
            .unwrap_or(0);

        if ip_count > config.connection_burst && can_burst == 0 {
            return Err(ConnectionLimitError::BurstExceeded);
        }

        self.total_connections.fetch_add(1, Ordering::Release);

        if max_per_site.is_some() {
            let counter = self.site_total_connections
                .entry(site_id.to_string())
                .or_insert_with(|| AtomicU32::new(0));
            counter.fetch_add(1, Ordering::Release);
        }

        {
            let counter = self.ip_connections.entry(client_ip).or_insert_with(|| AtomicU32::new(0));
            counter.fetch_add(1, Ordering::Release);
        }

        if max_per_site.is_some() {
            let site_ips = self.site_connections
                .entry(site_id.to_string())
                .or_insert_with(DashMap::new);
            let ip_counter = site_ips
                .entry(client_ip)
                .or_insert_with(|| AtomicU32::new(0));
            ip_counter.fetch_add(1, Ordering::Release);
        }

        if can_burst > 0 {
            if let Some(tokens) = self.ip_burst_tokens.get(&client_ip) {
                let _ =
                    tokens.fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
            }
        }

        Ok(ConnectionToken {
            site_id: site_id.to_string(),
            client_ip,
            acquired_at: Instant::now(),
        })
    }

    pub async fn check_site_limit(
        &self,
        site_id: &str,
        max_per_site: Option<u32>,
    ) -> Result<(), ConnectionLimitError> {
        let effective_max_per_site = max_per_site.unwrap_or(10000);
        let site_count = self.site_total_connections
                .get(site_id)
                .map(|c| c.load(Ordering::Acquire))
                .unwrap_or(0);

        if site_count >= effective_max_per_site {
            return Err(ConnectionLimitError::SiteLimitExceeded);
        }
        Ok(())
    }

    pub async fn acquire_with_queue(
        &self,
        site_id: &str,
        client_ip: IpAddr,
    ) -> Result<ConnectionToken, ConnectionLimitError> {
        let config = &self.config;

        if let Ok(token) = self.try_acquire(site_id, client_ip).await {
            return Ok(token);
        }

        let (tx, mut rx) = mpsc::channel(1);

        {
            let mut queue = self.connection_queue.write();
            if queue.len() >= config.connection_queue_size as usize {
                return Err(ConnectionLimitError::QueueFull);
            }
            queue.push(tx);
        }

        let result = timeout(
            Duration::from_millis(config.connection_queue_timeout_ms),
            rx.recv(),
        )
        .await;

        {
            let mut queue = self.connection_queue.write();
            queue.retain(|tx| !tx.is_closed());
        }

        match result {
            Ok(Some(_)) => self.try_acquire(site_id, client_ip).await,
            Ok(None) => Err(ConnectionLimitError::QueueClosed),
            Err(_) => Err(ConnectionLimitError::QueueTimeout),
        }
    }

    pub fn release(&self, token: ConnectionToken) {
        let _ = self
            .total_connections
            .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));

        {
            if let Some(counter) = self.site_total_connections.get(&token.site_id) {
                let prev = counter
                    .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
                if prev == Ok(1) {
                    drop(counter);
                    self.site_total_connections.remove(&token.site_id);
                }
            }
        }

        {
            if let Some(counter) = self.ip_connections.get(&token.client_ip) {
                let prev = counter
                    .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
                if prev == Ok(1) {
                    drop(counter);
                    self.ip_connections.remove(&token.client_ip);
                    self.ip_burst_tokens.insert(
                        token.client_ip,
                        AtomicU32::new(self.config.connection_burst),
                    );
                }
            }
        }

        {
            if let Some(site_ips) = self.site_connections.get(&token.site_id) {
                if let Some(counter) = site_ips.get(&token.client_ip) {
                    let prev = counter
                        .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
                    if prev == Ok(1) {
                        drop(counter);
                        site_ips.remove(&token.client_ip);
                    }
                }
                if site_ips.is_empty() {
                    drop(site_ips);
                    self.site_connections.remove(&token.site_id);
                }
            }
        }
    }

    pub fn active_connections(&self) -> u32 {
        self.total_connections.load(Ordering::Acquire)
    }

    pub fn active_connections_for_ip(&self, ip: IpAddr) -> u32 {
        self.ip_connections.get(&ip).map(|c| c.load(Ordering::Acquire)).unwrap_or(0)
    }

    pub fn config(&self) -> &ConnectionLimitsConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionLimitError {
    GlobalLimitExceeded,
    PerIpLimitExceeded,
    BurstExceeded,
    SiteLimitExceeded,
    QueueFull,
    QueueTimeout,
    QueueClosed,
}

impl std::fmt::Display for ConnectionLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionLimitError::GlobalLimitExceeded => {
                write!(f, "global connection limit exceeded")
            }
            ConnectionLimitError::PerIpLimitExceeded => {
                write!(f, "per-IP connection limit exceeded")
            }
            ConnectionLimitError::BurstExceeded => {
                write!(f, "connection burst limit exceeded")
            }
            ConnectionLimitError::QueueFull => {
                write!(f, "connection queue full")
            }
            ConnectionLimitError::QueueTimeout => {
                write!(f, "connection queue timeout")
            }
            ConnectionLimitError::QueueClosed => {
                write!(f, "connection queue closed")
            }
            ConnectionLimitError::SiteLimitExceeded => {
                write!(f, "per-site connection limit exceeded")
            }
        }
    }
}

impl std::error::Error for ConnectionLimitError {}

pub struct SiteConnectionLimiter {
    site_id: String,
    limiter: Arc<ConnectionLimiter>,
}

impl SiteConnectionLimiter {
    pub fn new(
        site_id: String,
        global_limiter: Arc<ConnectionLimiter>,
        _max_connections: Option<u32>,
        _max_connections_per_ip: Option<u32>,
        _queue_size: Option<u32>,
        _burst: Option<u32>,
    ) -> Self {
        Self {
            site_id,
            limiter: global_limiter,
        }
    }

    pub async fn try_acquire(
        &self,
        client_ip: IpAddr,
    ) -> Result<ConnectionToken, ConnectionLimitError> {
        self.limiter.try_acquire(&self.site_id, client_ip).await
    }

    pub async fn acquire_with_queue(
        &self,
        client_ip: IpAddr,
    ) -> Result<ConnectionToken, ConnectionLimitError> {
        self.limiter
            .acquire_with_queue(&self.site_id, client_ip)
            .await
    }

    pub fn release(&self, token: ConnectionToken) {
        self.limiter.release(token);
    }

    pub fn active_connections(&self) -> u32 {
        self.limiter.active_connections()
    }

    pub fn active_connections_for_ip(&self, ip: IpAddr) -> u32 {
        self.limiter.active_connections_for_ip(ip)
    }
}
