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

#[derive(Clone, Debug, PartialEq, Default)]
pub enum LoadBalanceAlgorithm {
    #[default]
    RoundRobin,
    Random,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Copy, Default)]
pub enum BackendProtocol {
    #[default]
    Http,
    Https,
    WebSocket,
    Wss,
    Grpc,
    GrpcTls,
    Tcp,
    QuicTunnel,
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
        let result =
            self.current_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        if result.is_err() {
            tracing::warn!("Attempted to decrement connection count below zero");
        }
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
        let scaled = (value.clamp(0.0, 100.0) * 100.0) as u32;
        self.cpu_percent.store(scaled, Ordering::Relaxed);
    }

    pub fn get_memory_percent(&self) -> f32 {
        self.memory_percent.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_memory_percent(&self, value: f32) {
        let scaled = (value.clamp(0.0, 100.0) * 100.0) as u32;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_is_available() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert!(backend.is_available());

        backend.increment_connections();
        assert!(backend.is_available());

        backend.increment_connections();
        assert!(backend.is_available());
    }

    #[test]
    fn test_backend_max_connections() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(2);
        assert!(backend.is_available());

        backend.increment_connections();
        backend.increment_connections();
        assert!(!backend.is_available());
    }

    #[test]
    fn test_backend_connection_guard() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(2);
        assert_eq!(backend.current_connections.load(Ordering::Relaxed), 0);

        {
            let _guard = backend.connection_scope();
            assert_eq!(backend.current_connections.load(Ordering::Relaxed), 1);
        }

        assert_eq!(backend.current_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_backend_record_success_recovery() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert!(backend.is_healthy.is_running());

        backend.is_healthy.set(false);
        assert!(!backend.is_healthy.is_running());

        backend.record_success();
        assert!(!backend.is_healthy.is_running());

        backend.record_success();
        assert!(!backend.is_healthy.is_running());

        backend.record_success();
        assert!(backend.is_healthy.is_running());
    }

    #[test]
    fn test_backend_record_failure_circuit_breaker() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert!(backend.is_healthy.is_running());

        backend.record_failure();
        assert!(backend.is_healthy.is_running());

        backend.record_failure();
        assert!(backend.is_healthy.is_running());

        backend.record_failure();
        assert!(!backend.is_healthy.is_running());
    }

    #[test]
    fn test_backend_consecutive_failures_reset_on_success() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert_eq!(backend.consecutive_failures.load(Ordering::Relaxed), 0);

        backend.record_failure();
        backend.record_failure();
        assert_eq!(backend.consecutive_failures.load(Ordering::Relaxed), 2);

        backend.record_success();
        assert_eq!(backend.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_backend_consecutive_successes_reset_on_failure() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert_eq!(backend.consecutive_successes.load(Ordering::Relaxed), 0);

        backend.record_success();
        backend.record_success();
        assert_eq!(backend.consecutive_successes.load(Ordering::Relaxed), 2);

        backend.record_failure();
        assert_eq!(backend.consecutive_successes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_backend_load_calculation() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(10);
        assert_eq!(backend.load(), 0.0);

        backend.increment_connections();
        backend.increment_connections();
        backend.increment_connections();
        assert_eq!(backend.load(), 0.3);
    }

    #[test]
    fn test_upstream_pool_round_robin() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
                "http://127.0.0.1:8082".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let selected: Vec<_> = (0..6)
            .map(|_| pool.select_backend().unwrap().url.as_ref().clone())
            .collect();

        assert_eq!(selected[0], "http://127.0.0.1:8080");
        assert_eq!(selected[1], "http://127.0.0.1:8081");
        assert_eq!(selected[2], "http://127.0.0.1:8082");
        assert_eq!(selected[3], "http://127.0.0.1:8080");
        assert_eq!(selected[4], "http://127.0.0.1:8081");
        assert_eq!(selected[5], "http://127.0.0.1:8082");
    }

    #[test]
    fn test_upstream_pool_least_connections() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
                "http://127.0.0.1:8082".to_string(),
            ],
            LoadBalanceAlgorithm::LeastConnections,
        );

        {
            let backend = pool.select_backend().unwrap();
            backend.increment_connections();
        }

        {
            let backend = pool.select_backend().unwrap();
            backend.increment_connections();
        }

        {
            let backend = pool.select_backend().unwrap();
            backend.increment_connections();
        }

        let backend1 = pool.select_backend().unwrap();
        let _url1 = backend1.url.as_ref().clone();
        backend1.increment_connections();
        backend1.increment_connections();
        backend1.increment_connections();

        let backend2 = pool.select_backend().unwrap();
        backend2.increment_connections();
        backend2.increment_connections();

        let backend3 = pool.select_backend().unwrap();
        backend3.increment_connections();

        let load1 = backend1.load();
        let load2 = backend2.load();
        let load3 = backend3.load();

        assert!(load3 <= load2);
        assert!(load2 <= load1);
    }

    #[test]
    fn test_upstream_pool_least_connections_with_load() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::LeastConnections,
        );

        let backend1 = pool.select_backend().unwrap();
        backend1.increment_connections();
        backend1.increment_connections();
        backend1.increment_connections();

        let backend2 = pool.select_backend().unwrap();
        let url = backend2.url.as_ref().clone();
        backend2.increment_connections();

        assert_eq!(url, "http://127.0.0.1:8081");
    }

    #[test]
    fn test_upstream_pool_selects_only_healthy_backends() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");

        let backend = pool.select_backend().unwrap();
        assert_eq!(backend.url.as_ref(), "http://127.0.0.1:8081");
    }

    #[test]
    fn test_upstream_pool_returns_none_when_all_unhealthy() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");
        pool.mark_unhealthy("http://127.0.0.1:8081");

        assert!(pool.select_backend().is_none());
    }

    #[test]
    fn test_upstream_pool_backup_fallback() {
        let pool = UpstreamPool::new_with_backup(
            vec!["http://127.0.0.1:8080".to_string()],
            vec!["http://127.0.0.1:9090".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        assert_eq!(
            pool.select_backend().unwrap().url.as_ref(),
            "http://127.0.0.1:8080"
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");

        let backup = pool.select_backend().unwrap();
        assert_eq!(backup.url.as_ref(), "http://127.0.0.1:9090");
    }

    #[test]
    fn test_upstream_pool_backup_only_when_no_primaries() {
        let pool = UpstreamPool::new_with_backup(
            vec!["http://127.0.0.1:8080".to_string()],
            vec!["http://127.0.0.1:9090".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");

        let selected = pool.select_backend().unwrap();
        assert_eq!(selected.url.as_ref(), "http://127.0.0.1:9090");
        assert!(selected.is_backup);
    }

    #[test]
    fn test_upstream_pool_add_backend() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        assert!(pool.select_backend().is_some());

        pool.add_backend("http://127.0.0.1:8081".to_string());

        let backends = pool.get_backends();
        assert_eq!(backends.len(), 2);
    }

    #[test]
    fn test_upstream_pool_add_backend_no_duplicate() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.add_backend("http://127.0.0.1:8080".to_string());

        let backends = pool.get_backends();
        assert_eq!(backends.len(), 1);
    }

    #[test]
    fn test_upstream_pool_remove_backend() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.remove_backend("http://127.0.0.1:8080");

        let backends = pool.get_backends();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].url.as_ref(), "http://127.0.0.1:8081");
    }

    #[test]
    fn test_upstream_pool_mark_healthy() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");
        assert!(!pool.select_backend().is_some());

        pool.mark_healthy("http://127.0.0.1:8080");
        assert!(pool.select_backend().is_some());
    }

    #[test]
    fn test_upstream_pool_mark_unhealthy() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");
        assert!(pool.select_backend().is_none());
    }

    #[test]
    fn test_upstream_pool_get_metrics() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let metrics = pool.get_metrics();
        assert_eq!(metrics.total_backends, 2);
        assert_eq!(metrics.healthy_backends, 2);
        assert_eq!(metrics.unhealthy_backends, 0);
    }

    #[test]
    fn test_upstream_pool_get_metrics_with_unhealthy() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");

        let metrics = pool.get_metrics();
        assert_eq!(metrics.total_backends, 2);
        assert_eq!(metrics.healthy_backends, 1);
        assert_eq!(metrics.unhealthy_backends, 1);
    }

    #[test]
    fn test_upstream_pool_mark_failed() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_failed("http://127.0.0.1:8080");
        pool.mark_failed("http://127.0.0.1:8080");
        pool.mark_failed("http://127.0.0.1:8080");

        assert!(pool.select_backend().is_none());
    }

    #[test]
    fn test_upstream_pool_has_primaries() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        assert!(pool.has_primaries());

        pool.mark_unhealthy("http://127.0.0.1:8080");
        pool.mark_unhealthy("http://127.0.0.1:8081");

        assert!(!pool.has_primaries());
    }

    #[test]
    fn test_upstream_pool_select_next_backend() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
                "http://127.0.0.1:8082".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let current = pool.select_backend().unwrap();
        let current_url = current.url.as_ref().clone();

        let next = pool.select_next_backend(&current);
        assert!(next.is_some());
        assert_ne!(next.unwrap().url.as_ref(), &current_url);
    }

    #[test]
    fn test_validate_upstream_url() {
        assert_eq!(
            validate_upstream_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_upstream_url("https://example.com").unwrap(),
            "https://example.com"
        );
        assert!(validate_upstream_url("").is_err());
        assert!(validate_upstream_url("ftp://example.com").is_err());
        assert!(validate_upstream_url("file:///etc/passwd").is_err());
        assert_eq!(validate_upstream_url("/path").unwrap(), "/path");
    }

    #[test]
    fn test_backend_try_new_valid() {
        let backend = Backend::try_new("http://127.0.0.1:8080".to_string());
        assert!(backend.is_ok());
        assert_eq!(backend.unwrap().url.as_ref(), "http://127.0.0.1:8080");
    }

    #[test]
    fn test_backend_try_new_invalid() {
        let result = Backend::try_new("ftp://127.0.0.1:8080".to_string());
        match result {
            Ok(_) => panic!("Expected error for invalid scheme"),
            Err(e) => assert!(e.contains("Invalid upstream URL scheme")),
        }
    }

    #[test]
    fn test_backend_with_weight() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_weight(5);
        assert_eq!(backend.weight, 5);
    }

    #[test]
    fn test_backend_with_protocol() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string())
            .with_protocol(BackendProtocol::GrpcTls);
        assert_eq!(backend.protocol, BackendProtocol::GrpcTls);
    }

    #[test]
    fn test_backend_supports_grpc() {
        let http_backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert!(!http_backend.supports_grpc());

        let grpc_backend =
            Backend::new("http://127.0.0.1:8080".to_string()).with_protocol(BackendProtocol::Grpc);
        assert!(grpc_backend.supports_grpc());

        let grpc_tls_backend = Backend::new("http://127.0.0.1:8080".to_string())
            .with_protocol(BackendProtocol::GrpcTls);
        assert!(grpc_tls_backend.supports_grpc());
    }

    #[test]
    fn test_backend_supports_websocket() {
        let http_backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert!(!http_backend.supports_websocket());

        let ws_backend = Backend::new("http://127.0.0.1:8080".to_string())
            .with_protocol(BackendProtocol::WebSocket);
        assert!(ws_backend.supports_websocket());

        let wss_backend =
            Backend::new("http://127.0.0.1:8080".to_string()).with_protocol(BackendProtocol::Wss);
        assert!(wss_backend.supports_websocket());
    }

    #[test]
    fn test_backend_new_backup() {
        let primary = Backend::new("http://127.0.0.1:8080".to_string());
        let backup = Backend::new_backup("http://127.0.0.1:9090".to_string());

        assert!(!primary.is_backup);
        assert!(backup.is_backup);
    }

    #[test]
    fn test_backend_composite_load() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(10);
        backend.increment_connections();
        backend.increment_connections();

        let load = backend.composite_load();
        assert!(load > 0.0);
        assert!(load <= 1.0);
    }

    #[test]
    fn test_backend_cpu_percent() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert_eq!(backend.get_cpu_percent(), 0.0);

        backend.set_cpu_percent(50.0);
        assert_eq!(backend.get_cpu_percent(), 50.0);
    }

    #[test]
    fn test_backend_memory_percent() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert_eq!(backend.get_memory_percent(), 0.0);

        backend.set_memory_percent(75.0);
        assert_eq!(backend.get_memory_percent(), 75.0);
    }

    #[test]
    fn test_load_balance_algorithm_default() {
        let algorithm: LoadBalanceAlgorithm = Default::default();
        assert_eq!(algorithm, LoadBalanceAlgorithm::RoundRobin);
    }

    #[test]
    fn test_backend_protocol_default() {
        let protocol: BackendProtocol = Default::default();
        assert_eq!(protocol, BackendProtocol::Http);
    }

    #[test]
    fn test_upstream_pool_with_max_connections_enforcement() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let backend = pool.select_backend().unwrap();
        let backend = backend.with_max_connections(1);

        backend.increment_connections();
        assert!(!backend.is_available());
    }

    #[test]
    fn test_upstream_pool_select_backend_for_ip() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::IpHash,
        );

        let backend1 = pool.select_backend_for_ip("192.168.1.1");
        let backend2 = pool.select_backend_for_ip("192.168.1.2");

        assert!(backend1.is_some());
        assert!(backend2.is_some());
    }

    #[test]
    fn test_upstream_pool_select_backend_for_ip_same_client() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::IpHash,
        );

        let backend1 = pool.select_backend_for_ip("192.168.1.100");
        let backend2 = pool.select_backend_for_ip("192.168.1.100");

        assert_eq!(
            backend1.unwrap().url.as_ref(),
            backend2.unwrap().url.as_ref()
        );
    }

    #[test]
    fn test_upstream_pool_select_backend_for_protocol() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.add_backend_with_protocol("http://127.0.0.1:8082".to_string(), BackendProtocol::Grpc);

        let grpc_backend = pool.select_backend_for_protocol(BackendProtocol::Grpc);
        assert!(grpc_backend.is_some());
        assert_eq!(grpc_backend.unwrap().url.as_ref(), "http://127.0.0.1:8082");
    }

    #[test]
    fn test_upstream_pool_select_backend_for_protocol_none_available() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let grpc_backend = pool.select_backend_for_protocol(BackendProtocol::Grpc);
        assert!(grpc_backend.is_none());
    }

    #[test]
    fn test_upstream_pool_add_backend_with_weight() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.add_backend_with_weight(
            "http://127.0.0.1:8081".to_string(),
            5,
            BackendProtocol::Http,
        );

        let backends = pool.get_backends();
        let backend = backends
            .iter()
            .find(|b| b.url.as_ref() == "http://127.0.0.1:8081")
            .unwrap();
        assert_eq!(backend.weight, 5);
    }

    #[test]
    fn test_upstream_pool_update_backend_weight() {
        let pool = UpstreamPool::new(
            vec!["http://127.0.0.1:8080".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.add_backend_with_weight(
            "http://127.0.0.1:8080".to_string(),
            10,
            BackendProtocol::Http,
        );

        let backends = pool.get_backends();
        let backend = &backends[0];
        assert_eq!(backend.weight, 10);
    }

    #[test]
    fn test_connection_guard_decrement_on_drop() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(10);

        backend.increment_connections();
        backend.increment_connections();
        assert_eq!(backend.current_connections.load(Ordering::Relaxed), 2);

        {
            let _guard = backend.connection_scope();
            assert_eq!(backend.current_connections.load(Ordering::Relaxed), 3);
        }

        assert_eq!(backend.current_connections.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_connection_guard_prevents_underflow() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(10);

        {
            let _guard = backend.connection_scope();
        }

        assert_eq!(backend.current_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_upstream_metrics_average_load() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let backend1 = pool.select_backend().unwrap();
        backend1.increment_connections();
        backend1.increment_connections();

        let metrics = pool.get_metrics();
        assert_eq!(metrics.total_connections, 2);
    }
}
