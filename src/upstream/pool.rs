use parking_lot::RwLock;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

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

pub struct ConnectionGuard<'a> {
    backend: &'a Backend,
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        self.backend.decrement_connections();
    }
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
        matches!(
            self.protocol,
            BackendProtocol::Grpc | BackendProtocol::GrpcTls
        )
    }

    pub fn supports_websocket(&self) -> bool {
        matches!(
            self.protocol,
            BackendProtocol::WebSocket | BackendProtocol::Wss
        )
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
        let _ = self
            .current_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    #[inline]
    pub fn connection_scope(&self) -> ConnectionGuard {
        self.increment_connections();
        ConnectionGuard { backend: self }
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
            tracing::warn!(
                "Backend {} marked as unhealthy after {} failures",
                self.url,
                failures
            );
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
        let conn_load =
            self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64;
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
}

impl UpstreamPool {
    pub fn new(urls: Vec<String>, algorithm: LoadBalanceAlgorithm) -> Self {
        let backends: Vec<Backend> = urls.into_iter().map(Backend::new).collect();

        Self {
            backends: Arc::new(RwLock::new(backends)),
            algorithm,
            round_robin_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn new_with_backup(
        urls: Vec<String>,
        backup_urls: Vec<String>,
        algorithm: LoadBalanceAlgorithm,
    ) -> Self {
        let mut backends: Vec<Backend> = urls.into_iter().map(Backend::new).collect();

        let backups: Vec<Backend> = backup_urls.into_iter().map(Backend::new_backup).collect();

        backends.extend(backups);

        Self {
            backends: Arc::new(RwLock::new(backends)),
            algorithm,
            round_robin_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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

    fn apply_round_robin(&self, candidates: &[&Backend]) -> Option<Backend> {
        let len = candidates.len();
        if len == 0 {
            return None;
        }
        let start_idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % len;
        Some(candidates[start_idx].clone())
    }

    fn apply_random(&self, candidates: &[&Backend]) -> Option<Backend> {
        let len = candidates.len();
        if len == 0 {
            return None;
        }
        use rand::Rng;
        let mut rng = rand::rng();
        let idx = rng.random_range(0..len);
        Some(candidates[idx].clone())
    }

    fn apply_least_connections(&self, candidates: &[&Backend]) -> Option<Backend> {
        candidates
            .iter()
            .map(|b| (b.composite_load(), *b))
            .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(_, b)| b.clone())
    }

    fn apply_ip_hash(
        &self,
        candidates: &[&Backend],
        client_ip_hint: Option<&str>,
    ) -> Option<Backend> {
        let len = candidates.len();
        if len == 0 {
            return None;
        }
        let hash = if let Some(ip) = client_ip_hint {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(ip.as_bytes(), &mut hasher);
            std::hash::Hasher::finish(&hasher) as usize
        } else {
            self.round_robin_index.fetch_add(1, Ordering::Relaxed)
        };
        let idx = hash % len;
        Some(candidates[idx].clone())
    }

    fn filter_candidates<'a>(
        &self,
        backends: &'a [Backend],
        backup_only: bool,
    ) -> Vec<&'a Backend> {
        backends
            .iter()
            .filter(|b| b.is_backup == backup_only && b.is_available())
            .collect()
    }

    fn apply_algorithm(&self, candidates: &[&Backend]) -> Option<Backend> {
        match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => self.apply_round_robin(candidates),
            LoadBalanceAlgorithm::Random => self.apply_random(candidates),
            LoadBalanceAlgorithm::LeastConnections => self.apply_least_connections(candidates),
            LoadBalanceAlgorithm::WeightedRoundRobin => self
                .weighted_round_robin(&candidates.iter().map(|b| (*b).clone()).collect::<Vec<_>>()),
            LoadBalanceAlgorithm::IpHash => self.apply_ip_hash(candidates, None),
        }
    }

    fn select_from_backends(&self, backends: &[Backend], backup_only: bool) -> Option<Backend> {
        let candidates = self.filter_candidates(backends, backup_only);

        if candidates.is_empty() {
            return None;
        }

        self.apply_algorithm(&candidates)
    }

    pub fn select_next_backend(&self, current: &Backend) -> Option<Backend> {
        let backends = self.backends.read();
        let current_is_backup = current.is_backup;

        let candidates: Vec<&Backend> = backends
            .iter()
            .filter(|b| {
                b.url != current.url && b.is_available() && b.is_backup == current_is_backup
            })
            .collect();

        let result = self.apply_algorithm(&candidates);

        if result.is_some() {
            return result;
        }

        if !current_is_backup {
            backends
                .iter()
                .find(|b| b.is_backup && b.is_available())
                .cloned()
        } else {
            None
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
        if !matches!(self.algorithm, LoadBalanceAlgorithm::IpHash) {
            return self.select_backend();
        }

        let backends = self.backends.read();
        let candidates: Vec<&Backend> = backends.iter().filter(|b| b.is_available()).collect();

        if candidates.is_empty() {
            return None;
        }

        let hash = self.get_or_create_hash(client_ip, candidates.len());
        let idx = hash % candidates.len();

        Some(candidates[idx].clone())
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
            tracing::info!(
                "Updated backend {} with weight {} and protocol {:?}",
                url,
                weight,
                protocol
            );
        } else {
            backends.push(
                Backend::new(url.clone())
                    .with_weight(weight)
                    .with_protocol(protocol),
            );
            tracing::info!(
                "Added {} backend with weight {} and protocol {:?}",
                url,
                weight,
                protocol
            );
        }
    }

    fn filter_by_protocol<'a>(
        &self,
        backends: &'a [Backend],
        protocol: BackendProtocol,
    ) -> Vec<&'a Backend> {
        backends
            .iter()
            .filter(|b| b.is_available() && b.protocol == protocol)
            .collect()
    }

    pub fn select_backend_for_protocol(
        &self,
        required_protocol: BackendProtocol,
    ) -> Option<Backend> {
        let backends = self.backends.read();
        let candidates = self.filter_by_protocol(&backends, required_protocol);

        if candidates.is_empty() {
            tracing::warn!("No available backends for protocol {:?}", required_protocol);
            return None;
        }

        self.apply_algorithm(&candidates)
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

    fn with_backend<F>(&self, url: &str, f: F)
    where
        F: FnOnce(&Backend),
    {
        let backends = self.backends.read();
        if let Some(backend) = backends.iter().find(|b| b.url.as_ref() == url) {
            f(backend);
        }
    }

    pub fn mark_healthy(&self, url: &str) {
        self.with_backend(url, |backend| {
            backend.is_healthy.set(true);
            tracing::info!("Backend {} marked healthy", url);
        });
    }

    pub fn mark_unhealthy(&self, url: &str) {
        self.with_backend(url, |backend| {
            backend.is_healthy.set(false);
            tracing::info!("Backend {} marked unhealthy", url);
        });
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
