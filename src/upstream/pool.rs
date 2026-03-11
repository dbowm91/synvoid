use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use parking_lot::RwLock;

use crate::RunningFlag;

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
    pub url: Arc<String>,
    pub weight: u32,
    pub max_connections: usize,
    pub current_connections: Arc<AtomicUsize>,
    pub is_healthy: RunningFlag,
    pub consecutive_failures: Arc<AtomicU32>,
    pub consecutive_successes: Arc<AtomicU32>,
    pub protocol: BackendProtocol,
    pub is_backup: bool,
    pub cpu_percent: Arc<AtomicU32>,
    pub memory_percent: Arc<AtomicU32>,
}

impl Backend {
    fn new_internal(url: String, is_backup: bool) -> Self {
        let validated_url = validate_upstream_url(&url).unwrap_or_else(|e| {
            tracing::error!("Invalid upstream URL '{}': {}", url, e);
            url
        });
        Self {
            url: Arc::new(validated_url),
            weight: 1,
            max_connections: 100,
            current_connections: Arc::new(AtomicUsize::new(0)),
            is_healthy: RunningFlag::new(),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            consecutive_successes: Arc::new(AtomicU32::new(0)),
            protocol: BackendProtocol::Http,
            is_backup,
            cpu_percent: Arc::new(AtomicU32::new(0)),
            memory_percent: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn new(url: String) -> Self {
        Self::new_internal(url, false)
    }

    pub fn try_new(url: String) -> Result<Self, String> {
        let validated_url = validate_upstream_url(&url)?;
        Ok(Self::new_internal(validated_url, false))
    }

    pub fn new_backup(url: String) -> Self {
        Self::new_internal(url, true)
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

    #[inline]
    pub fn is_available(&self) -> bool {
        self.is_healthy.is_running() 
            && self.current_connections.load(Ordering::Relaxed) < self.max_connections
    }

    #[inline]
    pub fn increment_connections(&self) {
        self.current_connections.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn decrement_connections(&self) {
        self.current_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        if successes >= 3 && !self.is_healthy.is_running() {
            self.is_healthy.set(true);
        }
    }

    pub fn record_failure(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= 3 && self.is_healthy.is_running() {
            self.is_healthy.set(false);
            tracing::warn!("Backend {} marked as unhealthy after {} failures", self.url, failures);
        }
    }

    pub fn load(&self) -> f64 {
        self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64
    }

    pub fn get_cpu_percent(&self) -> f32 {
        self.cpu_percent.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_cpu_percent(&self, value: f32) {
        let scaled = (value.min(100.0).max(0.0) * 100.0) as u32;
        self.cpu_percent.store(scaled, Ordering::Relaxed);
    }

    pub fn get_memory_percent(&self) -> f32 {
        self.memory_percent.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_memory_percent(&self, value: f32) {
        let scaled = (value.min(100.0).max(0.0) * 100.0) as u32;
        self.memory_percent.store(scaled, Ordering::Relaxed);
    }

    pub fn composite_load(&self) -> f64 {
        let conn_load = self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64;
        let cpu_load = self.get_cpu_percent() as f64;
        let _mem_load = self.get_memory_percent() as f64;
        (conn_load * 0.4) + (cpu_load * 0.6)
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

    pub fn select_backend(&self) -> Option<Backend> {
        let backends = self.backends.read();
        
        if let Some(backend) = self.select_from_backends(&backends, false) {
            return Some(backend);
        }
        
        self.select_from_backends(&backends, true)
    }

    pub fn try_select_backend(&self) -> Option<Backend> {
        let backends = self.backends.try_read()?;
        
        if let Some(backend) = self.select_from_backends(&backends, false) {
            return Some(backend);
        }
        
        self.select_from_backends(&backends, true)
    }

    fn select_from_backends(&self, backends: &[Backend], backup_only: bool) -> Option<Backend> {
        let len = backends.len();
        if len == 0 {
            return None;
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let start_idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % len;
                
                for offset in 0..len {
                    let idx = (start_idx + offset) % len;
                    let b = &backends[idx];
                    if b.is_backup == backup_only && b.is_available() {
                        return Some(b.clone());
                    }
                }
                None
            }
            LoadBalanceAlgorithm::Random => {
                use rand::Rng;
                let mut rng = rand::rng();
                
                let available_count = backends.iter()
                    .filter(|b| b.is_backup == backup_only && b.is_available())
                    .count();
                
                if available_count == 0 {
                    return None;
                }
                
                let target = rng.random_range(0..available_count);
                
                let mut count = 0;
                for b in backends.iter() {
                    if b.is_backup == backup_only && b.is_available() {
                        if count == target {
                            return Some(b.clone());
                        }
                        count += 1;
                    }
                }
                
                None
            }
            LoadBalanceAlgorithm::LeastConnections => {
                let mut best: Option<(f64, &Backend)> = None;
                
                for b in backends.iter() {
                    if b.is_backup == backup_only && b.is_available() {
                        let load = b.composite_load();
                        match best {
                            None => best = Some((load, b)),
                            Some((best_load, _)) if load < best_load => best = Some((load, b)),
                            _ => {}
                        }
                    }
                }
                
                best.map(|(_, b)| b.clone())
            }
            LoadBalanceAlgorithm::WeightedRoundRobin => {
                None
            }
            LoadBalanceAlgorithm::IpHash => {
                backends.iter()
                    .find(|b| b.is_backup == backup_only && b.is_available())
                    .cloned()
            }
        }
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
                let mut rng = rand::rng();
                let idx = rng.random_range(0..available.len());
                Some(available[idx].clone())
            }
            LoadBalanceAlgorithm::LeastConnections => {
                available.iter()
                    .map(|b| (b.composite_load(), b))
                    .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(_, b)| b.clone())
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
                let mut rng = rand::rng();
                let idx = rng.random_range(0..available.len());
                Some(available[idx].clone())
            }
            LoadBalanceAlgorithm::LeastConnections => {
                available.iter()
                    .map(|b| (b.composite_load(), b))
                    .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(_, b)| b.clone())
            }
            LoadBalanceAlgorithm::WeightedRoundRobin => {
                self.weighted_round_robin(&available)
            }
            LoadBalanceAlgorithm::IpHash => {
                available.first().cloned()
            }
        }
    }

    pub fn select_next_backend(&self, current: &Backend) -> Option<Backend> {
        let backends = self.backends.read();
        let current_is_backup = current.is_backup;
        let current_url = &current.url;
        
        let len = backends.len();
        if len == 0 {
            return None;
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let start_idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % len;
                
                for offset in 0..len {
                    let idx = (start_idx + offset) % len;
                    let b = &backends[idx];
                    if b.url != *current_url && b.is_available() && b.is_backup == current_is_backup {
                        return Some(b.clone());
                    }
                }
                
                if !current_is_backup {
                    for b in backends.iter() {
                        if b.is_backup && b.is_available() {
                            return Some(b.clone());
                        }
                    }
                }
                
                None
            }
            LoadBalanceAlgorithm::LeastConnections => {
                let mut best: Option<(f64, &Backend)> = None;
                
                for b in backends.iter() {
                    if b.url != *current_url && b.is_available() && b.is_backup == current_is_backup {
                        let load = b.composite_load();
                        match best {
                            None => best = Some((load, b)),
                            Some((best_load, _)) if load < best_load => best = Some((load, b)),
                            _ => {}
                        }
                    }
                }
                
                if let Some((_, b)) = best {
                    return Some(b.clone());
                }
                
                if !current_is_backup {
                    for b in backends.iter() {
                        if b.is_backup && b.is_available() {
                            return Some(b.clone());
                        }
                    }
                }
                
                None
            }
            _ => {
                for b in backends.iter() {
                    if b.url != *current_url && b.is_available() && b.is_backup == current_is_backup {
                        return Some(b.clone());
                    }
                }
                
                if !current_is_backup {
                    backends.iter()
                        .find(|b| b.is_backup && b.is_available())
                        .cloned()
                } else {
                    None
                }
            }
        }
    }

    pub fn has_primaries(&self) -> bool {
        let backends = self.backends.read();
        backends.iter().any(|b| !b.is_backup && b.is_available())
    }

    pub fn mark_failed(&self, url: &str) {
        let backends = self.backends.read();
        if let Some(backend) = backends.iter().find(|b| b.url.as_ref() == url) {
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

    pub fn select_backend_for_ip(&self, client_ip: &str) -> Option<Backend> {
        if matches!(self.algorithm, LoadBalanceAlgorithm::IpHash) {
            let backends = self.backends.read();
            let len = backends.len();
            
            if len == 0 {
                return None;
            }

            let hash = self.get_or_create_hash(client_ip, len);
            let idx = hash % len;
            
            let backend = &backends[idx];
            if backend.is_available() {
                Some(backend.clone())
            } else {
                backends.iter().find(|b| b.is_available()).cloned()
            }
        } else {
            self.select_backend()
        }
    }

    #[inline]
    fn get_or_create_hash(&self, key: &str, num_backends: usize) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % num_backends
    }

    pub fn add_backend(&self, url: String) {
        let mut backends = self.backends.write();
        if !backends.iter().any(|b| b.url.as_ref() == &url) {
            backends.push(Backend::new(url));
            tracing::info!("Added backend to pool");
        }
    }

    pub fn add_backend_with_protocol(&self, url: String, protocol: BackendProtocol) {
        let mut backends = self.backends.write();
        if !backends.iter().any(|b| b.url.as_ref() == &url) {
            backends.push(Backend::new(url.clone()).with_protocol(protocol));
            tracing::info!("Added {} backend to pool", protocol_name(protocol));
        }
    }

    pub fn add_backend_with_weight(&self, url: String, weight: u32, protocol: BackendProtocol) {
        let mut backends = self.backends.write();
        if let Some(existing) = backends.iter_mut().find(|b| b.url.as_ref() == &url) {
            existing.weight = weight;
            existing.protocol = protocol;
            tracing::info!("Updated backend {} with weight {} and protocol {:?}", url, weight, protocol);
        } else {
            backends.push(Backend::new(url.clone()).with_weight(weight).with_protocol(protocol));
            tracing::info!("Added {} backend with weight {} and protocol {:?}", url, weight, protocol);
        }
    }

    pub fn select_backend_for_protocol(&self, required_protocol: BackendProtocol) -> Option<Backend> {
        let backends = self.backends.read();
        
        let mut best: Option<Backend> = None;
        let start_idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
        let len = backends.len();
        
        if len == 0 {
            tracing::warn!("No available backends for protocol {:?}", required_protocol);
            return None;
        }

        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin | LoadBalanceAlgorithm::LeastConnections | LoadBalanceAlgorithm::IpHash => {
                for offset in 0..len {
                    let idx = (start_idx + offset) % len;
                    let b = &backends[idx];
                    if b.is_available() && b.protocol == required_protocol {
                        best = Some(b.clone());
                        break;
                    }
                }
                
                if best.is_none() {
                    for b in backends.iter() {
                        if b.is_available() && b.protocol == required_protocol {
                            best = Some(b.clone());
                            break;
                        }
                    }
                }
                
                if best.is_none() {
                    tracing::warn!("No available backends for protocol {:?}", required_protocol);
                }
                
                best
            }
            LoadBalanceAlgorithm::Random => {
                use rand::Rng;
                let mut rng = rand::rng();
                let idx = rng.random_range(0..len);
                let mut found = None;
                
                for offset in 0..len {
                    let i = (idx + offset) % len;
                    let b = &backends[i];
                    if b.is_available() && b.protocol == required_protocol {
                        found = Some(b.clone());
                        break;
                    }
                }
                
                if found.is_none() {
                    tracing::warn!("No available backends for protocol {:?}", required_protocol);
                }
                
                found
            }
            _ => {
                backends.iter()
                    .find(|b| b.is_available() && b.protocol == required_protocol)
                    .cloned()
            }
        }
    }

    pub fn remove_backend(&self, url: &str) {
        let mut backends = self.backends.write();
        backends.retain(|b| b.url.as_ref() != url);
        tracing::info!("Removed backend {} from pool", url);
    }

    pub fn get_backends(&self) -> parking_lot::RwLockReadGuard<'_, Vec<Backend>> {
        self.backends.read()
    }

    pub fn get_metrics(&self) -> UpstreamMetrics {
        let backends = self.backends.read();
        
        let mut healthy_count = 0;
        let mut unhealthy_count = 0;
        let mut total_connections = 0;
        let mut avg_load = 0.0;

        for backend in backends.iter() {
            total_connections += backend.current_connections.load(Ordering::Relaxed);
            if backend.is_healthy.is_running() {
                healthy_count += 1;
                avg_load += backend.load();
            } else {
                unhealthy_count += 1;
            }
        }

        let total_backends = backends.len();
        
        if !backends.is_empty() {
            avg_load /= healthy_count.max(1) as f64;
        }

        UpstreamMetrics {
            total_backends,
            healthy_backends: healthy_count,
            unhealthy_backends: unhealthy_count,
            total_connections,
            average_load: avg_load,
        }
    }

    pub fn mark_healthy(&self, url: &str) {
        let backends = self.backends.read();
        if let Some(backend) = backends.iter().find(|b| b.url.as_ref() == url) {
            backend.is_healthy.set(true);
            tracing::info!("Backend {} marked healthy", url);
        }
    }

    pub fn mark_unhealthy(&self, url: &str) {
        let backends = self.backends.read();
        if let Some(backend) = backends.iter().find(|b| b.url.as_ref() == url) {
            backend.is_healthy.set(false);
            tracing::info!("Backend {} marked unhealthy", url);
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
