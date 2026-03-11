use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use std::collections::VecDeque;
use metrics::{gauge, histogram};

const ALLOWED_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "grpc", "grpcs"];

fn validate_upstream_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    
    if url.is_empty() {
        return Err("Upstream URL cannot be empty".to_string());
    }
    
    if url.starts_with('/') || url.starts_with("./") {
        return Ok(url.to_string());
    }
    
    let scheme_end = url.find("://");
    if let Some(pos) = scheme_end {
        let scheme = &url[..pos];
        if !ALLOWED_SCHEMES.contains(&scheme) {
            return Err(format!(
                "Invalid upstream URL scheme '{}': only {:?} are allowed",
                scheme, ALLOWED_SCHEMES
            ));
        }
    } else if !url.contains(':') {
        return Err(format!(
            "Upstream URL '{}' must include a scheme (http://, https://, etc.)",
            url
        ));
    }
    
    if url.contains("file://") || url.contains("ftp://") || url.contains("gopher://") {
        return Err(format!("Unsafe scheme in upstream URL: {}", url));
    }
    
    Ok(url.to_string())
}

#[derive(Clone, Debug, PartialEq)]
pub enum LoadBalanceAlgorithm {
    RoundRobin,
    Random,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
}

impl Default for LoadBalanceAlgorithm {
    fn default() -> Self {
        Self::RoundRobin
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub enum BackendProtocol {
    Http,
    Https,
    WebSocket,
    Wss,
    Grpc,
    GrpcTls,
    Tcp,
    QuicTunnel,
}

impl Default for BackendProtocol {
    fn default() -> Self {
        Self::Http
    }
}

fn protocol_name(protocol: BackendProtocol) -> &'static str {
    match protocol {
        BackendProtocol::Http => "HTTP",
        BackendProtocol::Https => "HTTPS",
        BackendProtocol::WebSocket => "WebSocket",
        BackendProtocol::Wss => "WSS",
        BackendProtocol::Grpc => "gRPC",
        BackendProtocol::GrpcTls => "gRPC-TLS",
        BackendProtocol::Tcp => "TCP",
        BackendProtocol::QuicTunnel => "QUIC-TUNNEL",
    }
}

#[derive(Clone)]
pub struct Backend {
    pub url: String,
    pub weight: u32,
    pub max_connections: usize,
    pub current_connections: Arc<AtomicUsize>,
    pub is_healthy: Arc<std::sync::atomic::AtomicBool>,
    pub consecutive_failures: Arc<AtomicU32>,
    pub consecutive_successes: Arc<AtomicU32>,
    pub protocol: BackendProtocol,
    pub is_backup: bool,
}

impl Backend {
    pub fn new(url: String) -> Self {
        let validated_url = validate_upstream_url(&url).unwrap_or_else(|e| {
            tracing::error!("Invalid upstream URL '{}': {}", url, e);
            url
        });
        Self {
            url: validated_url,
            weight: 1,
            max_connections: 100,
            current_connections: Arc::new(AtomicUsize::new(0)),
            is_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            consecutive_successes: Arc::new(AtomicU32::new(0)),
            protocol: BackendProtocol::Http,
            is_backup: false,
        }
    }

    pub fn try_new(url: String) -> Result<Self, String> {
        let validated_url = validate_upstream_url(&url)?;
        Ok(Self {
            url: validated_url,
            weight: 1,
            max_connections: 100,
            current_connections: Arc::new(AtomicUsize::new(0)),
            is_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            consecutive_successes: Arc::new(AtomicU32::new(0)),
            protocol: BackendProtocol::Http,
            is_backup: false,
        })
    }

    pub fn new_backup(url: String) -> Self {
        let validated_url = validate_upstream_url(&url).unwrap_or_else(|e| {
            tracing::error!("Invalid backup upstream URL '{}': {}", url, e);
            url
        });
        Self {
            url: validated_url,
            weight: 1,
            max_connections: 100,
            current_connections: Arc::new(AtomicUsize::new(0)),
            is_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            consecutive_successes: Arc::new(AtomicU32::new(0)),
            protocol: BackendProtocol::Http,
            is_backup: true,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn with_backup(mut self, is_backup: bool) -> Self {
        self.is_backup = is_backup;
        self
    }

    pub fn supports_grpc(&self) -> bool {
        matches!(self.protocol, BackendProtocol::Grpc | BackendProtocol::GrpcTls)
    }

    pub fn supports_websocket(&self) -> bool {
        matches!(self.protocol, BackendProtocol::WebSocket | BackendProtocol::Wss)
    }

    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    pub fn is_available(&self) -> bool {
        self.is_healthy.load(Ordering::Relaxed) 
            && self.current_connections.load(Ordering::Relaxed) < self.max_connections
    }

    pub fn increment_connections(&self) {
        self.current_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.current_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        if successes >= 3 && !self.is_healthy.load(Ordering::Relaxed) {
            self.is_healthy.store(true, Ordering::Relaxed);
            tracing::info!("Backend {} marked as healthy", self.url);
        }
    }

    pub fn record_failure(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= 3 && self.is_healthy.load(Ordering::Relaxed) {
            self.is_healthy.store(false, Ordering::Relaxed);
            tracing::warn!("Backend {} marked as unhealthy after {} failures", self.url, failures);
        }
    }

    pub fn load(&self) -> f64 {
        self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64
    }
}

#[derive(Clone)]
pub struct UpstreamPool {
    backends: Arc<RwLock<Vec<Backend>>>,
    algorithm: LoadBalanceAlgorithm,
    round_robin_index: Arc<std::sync::atomic::AtomicUsize>,
    ip_hash_seeds: Arc<RwLock<std::collections::HashMap<String, usize>>>,
}

impl UpstreamPool {
    pub fn new(urls: Vec<String>, algorithm: LoadBalanceAlgorithm) -> Self {
        let backends: Vec<Backend> = urls.into_iter()
            .map(Backend::new)
            .collect();

        Self {
            backends: Arc::new(RwLock::new(backends)),
            algorithm,
            round_robin_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            ip_hash_seeds: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn new_with_backup(urls: Vec<String>, backup_urls: Vec<String>, algorithm: LoadBalanceAlgorithm) -> Self {
        let mut backends: Vec<Backend> = urls.into_iter()
            .map(Backend::new)
            .collect();
        
        let backups: Vec<Backend> = backup_urls.into_iter()
            .map(Backend::new_backup)
            .collect();
        
        backends.extend(backups);

        Self {
            backends: Arc::new(RwLock::new(backends)),
            algorithm,
            round_robin_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            ip_hash_seeds: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn select_backend(&self) -> Option<Backend> {
        let backends = self.backends.read().await;
        
        let primaries: Vec<Backend> = backends.iter()
            .filter(|b| !b.is_backup && b.is_available())
            .cloned()
            .collect();

        if !primaries.is_empty() {
            return self.select_from_list(&primaries).await;
        }

        let backups: Vec<Backend> = backends.iter()
            .filter(|b| b.is_backup && b.is_available())
            .cloned()
            .collect();

        if !backups.is_empty() {
            return self.select_from_list(&backups).await;
        }

        None
    }

    pub fn try_select_backend(&self) -> Option<Backend> {
        let backends = self.backends.try_read().ok()?;
        
        let primaries: Vec<Backend> = backends.iter()
            .filter(|b| !b.is_backup && b.is_available())
            .cloned()
            .collect();

        if !primaries.is_empty() {
            return self.select_from_list_sync(&primaries);
        }

        let backups: Vec<Backend> = backends.iter()
            .filter(|b| b.is_backup && b.is_available())
            .cloned()
            .collect();

        if !backups.is_empty() {
            return self.select_from_list_sync(&backups);
        }

        None
    }

    fn select_from_list_sync(&self, available: &[Backend]) -> Option<Backend> {
        if available.is_empty() {
            return None;
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % available.len();
                Some(available[idx].clone())
            }
            LoadBalanceAlgorithm::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..available.len());
                Some(available[idx].clone())
            }
            LoadBalanceAlgorithm::LeastConnections => {
                available.iter()
                    .min_by_key(|b| b.current_connections.load(Ordering::Relaxed))
                    .cloned()
            }
            LoadBalanceAlgorithm::WeightedRoundRobin => {
                None
            }
            LoadBalanceAlgorithm::IpHash => {
                available.first().cloned()
            }
        }
    }

    async fn select_from_list(&self, available: &[Backend]) -> Option<Backend> {
        if available.is_empty() {
            return None;
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % available.len();
                Some(available[idx].clone())
            }
            LoadBalanceAlgorithm::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..available.len());
                Some(available[idx].clone())
            }
            LoadBalanceAlgorithm::LeastConnections => {
                available.iter()
                    .min_by_key(|b| b.current_connections.load(Ordering::Relaxed))
                    .cloned()
            }
            LoadBalanceAlgorithm::WeightedRoundRobin => {
                self.weighted_round_robin(&available)
            }
            LoadBalanceAlgorithm::IpHash => {
                available.first().cloned()
            }
        }
    }

    pub async fn select_next_backend(&self, current: &Backend) -> Option<Backend> {
        let backends = self.backends.read().await;
        
        let current_is_backup = current.is_backup;
        
        let candidates: Vec<Backend> = backends.iter()
            .filter(|b| {
                b.url != current.url && 
                b.is_available() &&
                b.is_backup == current_is_backup
            })
            .cloned()
            .collect();

        if !candidates.is_empty() {
            return self.select_from_list(&candidates).await;
        }

        if !current_is_backup {
            let backups: Vec<Backend> = backends.iter()
                .filter(|b| b.is_backup && b.is_available())
                .cloned()
                .collect();
            
            if !backups.is_empty() {
                return self.select_from_list(&backups).await;
            }
        }

        None
    }

    pub async fn has_primaries(&self) -> bool {
        let backends = self.backends.read().await;
        backends.iter().any(|b| !b.is_backup && b.is_available())
    }

    pub async fn mark_failed(&self, url: &str) {
        let backends = self.backends.read().await;
        if let Some(backend) = backends.iter().find(|b| b.url == url) {
            backend.record_failure();
        }
    }

    fn weighted_round_robin(&self, available: &[Backend]) -> Option<Backend> {
        let total_weight: u32 = available.iter().map(|b| b.weight).sum();
        if total_weight == 0 {
            return available.first().cloned();
        }

        let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) as u32;
        let mut remainder = idx % total_weight;

        for backend in available {
            if remainder < backend.weight {
                return Some(backend.clone());
            }
            remainder -= backend.weight;
        }

        available.first().cloned()
    }

    pub async fn select_backend_for_ip(&self, client_ip: &str) -> Option<Backend> {
        if matches!(self.algorithm, LoadBalanceAlgorithm::IpHash) {
            let backends = self.backends.read().await;
            if backends.is_empty() {
                return None;
            }

            let hash = self.get_or_create_hash(client_ip, backends.len());
            let idx = hash % backends.len();
            
            let backend = backends[idx].clone();
            if backend.is_available() {
                Some(backend)
            } else {
                backends.iter().find(|b| b.is_available()).cloned()
            }
        } else {
            self.select_backend().await
        }
    }

    fn get_or_create_hash(&self, key: &str, num_backends: usize) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&key, &mut hasher);
        (std::hash::Hasher::finish(&hasher) as usize) % num_backends
    }

    pub async fn add_backend(&self, url: String) {
        let mut backends = self.backends.write().await;
        if !backends.iter().any(|b| b.url == url) {
            backends.push(Backend::new(url));
            tracing::info!("Added backend to pool");
        }
    }

    pub async fn add_backend_with_protocol(&self, url: String, protocol: BackendProtocol) {
        let mut backends = self.backends.write().await;
        if !backends.iter().any(|b| b.url == url) {
            backends.push(Backend::new(url.clone()).with_protocol(protocol));
            tracing::info!("Added {} backend to pool", protocol_name(protocol));
        }
    }

    pub async fn add_backend_with_weight(&self, url: String, weight: u32, protocol: BackendProtocol) {
        let mut backends = self.backends.write().await;
        if let Some(existing) = backends.iter_mut().find(|b| b.url == url) {
            existing.weight = weight;
            existing.protocol = protocol;
            tracing::info!("Updated backend {} with weight {} and protocol {:?}", url, weight, protocol);
        } else {
            backends.push(Backend::new(url.clone()).with_weight(weight).with_protocol(protocol));
            tracing::info!("Added {} backend to pool with weight {} and protocol {:?}", url, weight, protocol);
        }
    }

    pub async fn select_backend_for_protocol(&self, required_protocol: BackendProtocol) -> Option<Backend> {
        let backends = self.backends.read().await;
        
        let matching: Vec<Backend> = backends.iter()
            .filter(|b| b.is_available() && b.protocol == required_protocol)
            .cloned()
            .collect();

        if matching.is_empty() {
            tracing::warn!("No available backends for protocol {:?}", required_protocol);
            return None;
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % matching.len();
                Some(matching[idx].clone())
            }
            LoadBalanceAlgorithm::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..matching.len());
                Some(matching[idx].clone())
            }
            _ => matching.into_iter().next(),
        }
    }

    pub async fn remove_backend(&self, url: &str) {
        let mut backends = self.backends.write().await;
        backends.retain(|b| b.url != url);
        tracing::info!("Removed backend {} from pool", url);
    }

    pub async fn get_backends(&self) -> tokio::sync::RwLockReadGuard<'_, Vec<Backend>> {
        self.backends.read().await
    }

    pub async fn get_metrics(&self) -> UpstreamMetrics {
        let backends = self.backends.read().await;
        
        let mut healthy_count = 0;
        let mut unhealthy_count = 0;
        let mut total_connections = 0;
        let mut avg_load = 0.0;

        for backend in backends.iter() {
            if backend.is_healthy.load(Ordering::Relaxed) {
                healthy_count += 1;
            } else {
                unhealthy_count += 1;
            }
            total_connections += backend.current_connections.load(Ordering::Relaxed);
            avg_load += backend.load();
        }

        let backend_count = backends.len();
        if backend_count > 0 {
            avg_load /= backend_count as f64;
        }

        gauge!("rustwaf.upstream.healthy_backends").set(healthy_count as f64);
        gauge!("rustwaf.upstream.unhealthy_backends").set(unhealthy_count as f64);
        gauge!("rustwaf.upstream.total_connections").set(total_connections as f64);
        histogram!("rustwaf.upstream.backend_load").record(avg_load);

        UpstreamMetrics {
            total_backends: backend_count,
            healthy_backends: healthy_count,
            unhealthy_backends: unhealthy_count,
            total_connections,
            average_load: avg_load,
        }
    }

    pub async fn mark_unhealthy(&self, url: &str) {
        let backends = self.backends.read().await;
        if let Some(backend) = backends.iter().find(|b| b.url == url) {
            backend.is_healthy.store(false, Ordering::Relaxed);
            tracing::warn!("Backend {} marked unhealthy", url);
        }
    }

    pub async fn mark_healthy(&self, url: &str) {
        let backends = self.backends.read().await;
        if let Some(backend) = backends.iter().find(|b| b.url == url) {
            backend.is_healthy.store(true, Ordering::Relaxed);
            tracing::info!("Backend {} marked healthy", url);
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamMetrics {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
    pub total_connections: usize,
    pub average_load: f64,
}
