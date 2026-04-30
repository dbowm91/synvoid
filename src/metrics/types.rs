use crate::metrics::bandwidth::BandwidthTracker;
use crate::metrics::collection::LATENCY_SAMPLE_SIZE;
use crate::metrics::payloads::*;
use crate::waf::attack_detection::config::AttackType;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct SiteMetrics {
    pub total_requests: AtomicU64,
    pub blocked: AtomicU64,
    pub challenged: AtomicU64,
    pub proxied: AtomicU64,
    pub errors: AtomicU64,
    pub current_concurrent: AtomicU64,
    pub peak_concurrent: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub request_count: AtomicU64,
    pub upstream_successes: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub latency_samples: Mutex<Vec<u64>>,
    pub blocked_by_type: Mutex<HashMap<AttackType, AtomicU64>>,
}

impl Clone for SiteMetrics {
    fn clone(&self) -> Self {
        let blocked_types = self.blocked_by_type.lock();
        let mut blocked_by_type = HashMap::new();
        for (k, v) in blocked_types.iter() {
            blocked_by_type.insert(*k, AtomicU64::new(v.load(Ordering::Relaxed)));
        }
        drop(blocked_types);

        Self {
            total_requests: AtomicU64::new(self.total_requests.load(Ordering::Relaxed)),
            blocked: AtomicU64::new(self.blocked.load(Ordering::Relaxed)),
            challenged: AtomicU64::new(self.challenged.load(Ordering::Relaxed)),
            proxied: AtomicU64::new(self.proxied.load(Ordering::Relaxed)),
            errors: AtomicU64::new(self.errors.load(Ordering::Relaxed)),
            current_concurrent: AtomicU64::new(self.current_concurrent.load(Ordering::Relaxed)),
            peak_concurrent: AtomicU64::new(self.peak_concurrent.load(Ordering::Relaxed)),
            total_latency_ms: AtomicU64::new(self.total_latency_ms.load(Ordering::Relaxed)),
            request_count: AtomicU64::new(self.request_count.load(Ordering::Relaxed)),
            upstream_successes: AtomicU64::new(self.upstream_successes.load(Ordering::Relaxed)),
            upstream_failures: AtomicU64::new(self.upstream_failures.load(Ordering::Relaxed)),
            latency_samples: Mutex::new(Vec::new()),
            blocked_by_type: Mutex::new(blocked_by_type),
        }
    }
}

impl Default for SiteMetrics {
    fn default() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            challenged: AtomicU64::new(0),
            proxied: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            current_concurrent: AtomicU64::new(0),
            peak_concurrent: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            upstream_successes: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            latency_samples: Mutex::new(Vec::with_capacity(LATENCY_SAMPLE_SIZE)),
            blocked_by_type: Mutex::new(HashMap::new()),
        }
    }
}

impl SiteMetrics {
    pub fn record_request_start(&self) -> u64 {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let current = self.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        let mut peak = self.peak_concurrent.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_concurrent.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }
        current
    }

    pub fn record_request_end(&self, latency_ms: u64) {
        self.current_concurrent.fetch_sub(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);

        let mut samples = self.latency_samples.lock();
        if samples.len() < LATENCY_SAMPLE_SIZE {
            samples.push(latency_ms);
        } else {
            let idx = (self.request_count.load(Ordering::Relaxed) as usize) % LATENCY_SAMPLE_SIZE;
            samples[idx] = latency_ms;
        }
    }

    pub fn record_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_challenged(&self) {
        self.challenged.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxied(&self) {
        self.proxied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_success(&self) {
        self.upstream_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_failure(&self) {
        self.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn to_payload(&self, _site_id: &str) -> SiteMetricsPayload {
        let mut blocked_types = HashMap::new();
        let types = self.blocked_by_type.lock();
        for (k, v) in types.iter() {
            blocked_types.insert(format!("{:?}", k), v.load(Ordering::Relaxed));
        }

        let latency_samples = self.latency_samples.lock();
        let (avg, p50, p95, p99) = if !latency_samples.is_empty() {
            let mut sorted = latency_samples.clone();
            sorted.sort_unstable();
            let sum: u64 = sorted.iter().sum();
            let avg = sum as f64 / sorted.len() as f64;
            let p50 = sorted[sorted.len() / 2] as f64;
            let p95 = sorted[(sorted.len() as f64 * 0.95) as usize] as f64;
            let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)] as f64;
            (avg, p50, p95, p99)
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };

        SiteMetricsPayload {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            challenged: self.challenged.load(Ordering::Relaxed),
            proxied: self.proxied.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            current_concurrent: self.current_concurrent.load(Ordering::Relaxed),
            peak_concurrent: self.peak_concurrent.load(Ordering::Relaxed),
            avg_latency_ms: avg,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            blocked_by_type: blocked_types,
            upstream_healthy: true, // TODO: Wire actual health
            proxy_cache_hits: 0,
            proxy_cache_misses: 0,
            static_cache_hits: 0,
            static_cache_misses: 0,
            bytes_received: 0,
            bytes_sent: 0,
            proxied_bytes_sent: 0,
            proxied_bytes_received: 0,
            mesh_bytes_sent: 0,
            mesh_bytes_received: 0,
        }
    }
}

#[derive(Debug)]
pub struct WorkerMetrics {
    pub total_requests: AtomicU64,
    pub blocked: AtomicU64,
    pub challenged: AtomicU64,
    pub proxied: AtomicU64,
    pub errors: AtomicU64,
    pub current_concurrent: AtomicU64,
    pub peak_concurrent: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub request_count: AtomicU64,
    pub latency_samples: Mutex<Vec<u64>>,
    pub blocked_by_type: Mutex<HashMap<AttackType, AtomicU64>>,
    pub per_site: Mutex<HashMap<String, SiteMetrics>>,
    pub bandwidth: Arc<BandwidthTracker>,
    pub per_serverless: Mutex<HashMap<String, ServerlessMetrics>>,
}

impl Clone for WorkerMetrics {
    fn clone(&self) -> Self {
        let blocked_types = self.blocked_by_type.lock();
        let mut blocked_by_type = HashMap::new();
        for (k, v) in blocked_types.iter() {
            blocked_by_type.insert(*k, AtomicU64::new(v.load(Ordering::Relaxed)));
        }
        drop(blocked_types);

        Self {
            total_requests: AtomicU64::new(self.total_requests.load(Ordering::Relaxed)),
            blocked: AtomicU64::new(self.blocked.load(Ordering::Relaxed)),
            challenged: AtomicU64::new(self.challenged.load(Ordering::Relaxed)),
            proxied: AtomicU64::new(self.proxied.load(Ordering::Relaxed)),
            errors: AtomicU64::new(self.errors.load(Ordering::Relaxed)),
            current_concurrent: AtomicU64::new(self.current_concurrent.load(Ordering::Relaxed)),
            peak_concurrent: AtomicU64::new(self.peak_concurrent.load(Ordering::Relaxed)),
            total_latency_ms: AtomicU64::new(self.total_latency_ms.load(Ordering::Relaxed)),
            request_count: AtomicU64::new(self.request_count.load(Ordering::Relaxed)),
            latency_samples: Mutex::new(Vec::new()),
            blocked_by_type: Mutex::new(blocked_by_type),
            per_site: Mutex::new(HashMap::new()),
            bandwidth: self.bandwidth.clone(),
            per_serverless: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            challenged: AtomicU64::new(0),
            proxied: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            current_concurrent: AtomicU64::new(0),
            peak_concurrent: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            latency_samples: Mutex::new(Vec::with_capacity(LATENCY_SAMPLE_SIZE)),
            blocked_by_type: Mutex::new(HashMap::new()),
            per_site: Mutex::new(HashMap::new()),
            bandwidth: Arc::new(BandwidthTracker::default()),
            per_serverless: Mutex::new(HashMap::new()),
        }
    }
}

impl WorkerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn shared_with_bandwidth(_retention_days: u32, _mesh_excluded: bool) -> Arc<Self> {
        let metrics = Self::default();
        // bandwidth tracking is usually global or injected
        Arc::new(metrics)
    }

    pub fn record_request_start(&self) -> u64 {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let current = self.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        let mut peak = self.peak_concurrent.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_concurrent.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }
        current
    }

    pub fn record_request_end(&self, latency_ms: u64) {
        self.current_concurrent.fetch_sub(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);

        let mut samples = self.latency_samples.lock();
        if samples.len() < LATENCY_SAMPLE_SIZE {
            samples.push(latency_ms);
        } else {
            let idx = (self.request_count.load(Ordering::Relaxed) as usize) % LATENCY_SAMPLE_SIZE;
            samples[idx] = latency_ms;
        }
    }

    pub fn record_blocked(&self, attack_type: AttackType) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
        let mut blocked_types = self.blocked_by_type.lock();
        let counter = blocked_types
            .entry(attack_type)
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_challenged(&self) {
        self.challenged.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxied(&self) {
        self.proxied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn blocked(&self) -> u64 {
        self.blocked.load(Ordering::Relaxed)
    }

    pub fn challenged(&self) -> u64 {
        self.challenged.load(Ordering::Relaxed)
    }

    pub fn proxied(&self) -> u64 {
        self.proxied.load(Ordering::Relaxed)
    }

    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    pub fn current_load(&self) -> f64 {
        self.current_concurrent.load(Ordering::Relaxed) as f64
    }

    pub fn avg_latency_ms(&self) -> f64 {
        let count = self.request_count.load(Ordering::Relaxed);
        if count > 0 {
            self.total_latency_ms.load(Ordering::Relaxed) as f64 / count as f64
        } else {
            0.0
        }
    }

    pub fn requests_per_second(&self, uptime_secs: u64) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if uptime_secs > 0 {
            total as f64 / uptime_secs as f64
        } else {
            0.0
        }
    }

    pub fn blocked_by_type(&self) -> HashMap<AttackType, u64> {
        let blocked = self.blocked_by_type.lock();
        let mut result = HashMap::new();
        for (k, v) in blocked.iter() {
            result.insert(*k, v.load(Ordering::Relaxed));
        }
        result
    }

    const MAX_PER_SITE_ENTRIES: usize = 10000;

    pub fn record_site_request_start(&self, site_id: &str) -> u64 {
        let mut sites = self.per_site.lock();
        if sites.len() >= Self::MAX_PER_SITE_ENTRIES {
            sites.retain(|_, v| v.current_concurrent.load(Ordering::Relaxed) > 0);
        }
        if sites.len() >= Self::MAX_PER_SITE_ENTRIES {
            let key_to_remove = sites
                .iter()
                .find(|(_, v)| v.current_concurrent.load(Ordering::Relaxed) == 0)
                .map(|(k, _)| k.clone());
            if let Some(key) = key_to_remove {
                sites.remove(&key);
            }
        }
        let site = sites.entry(site_id.to_string()).or_default();
        site.record_request_start()
    }

    pub fn record_site_request_end(&self, site_id: &str, latency_ms: u64) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_request_end(latency_ms);
        }
    }

    pub fn record_site_blocked(&self, site_id: &str) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_blocked();
        }
    }

    pub fn record_site_challenged(&self, site_id: &str) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_challenged();
        }
    }

    pub fn record_site_proxied(&self, site_id: &str) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_proxied();
        }
    }

    pub fn record_site_error(&self, site_id: &str) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_error();
        }
    }

    pub fn record_site_upstream_success(&self, site_id: &str) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_upstream_success();
        }
    }

    pub fn record_site_upstream_failure(&self, site_id: &str) {
        let sites = self.per_site.lock();
        if let Some(site) = sites.get(site_id) {
            site.record_upstream_failure();
        }
    }

    pub fn to_payload(&self, uptime_secs: u64) -> WorkerMetricsPayload {
        let mut per_site = HashMap::new();
        let sites = self.per_site.lock();
        for (site_id, site_metrics) in sites.iter() {
            per_site.insert(site_id.clone(), site_metrics.to_payload(site_id));
        }

        let blocked_by_type = self.blocked_by_type();
        let mut blocked_by_type_str = HashMap::new();
        for (k, v) in blocked_by_type {
            blocked_by_type_str.insert(format!("{:?}", k), v);
        }

        let latency_samples = self.latency_samples.lock();
        let (avg, p50, p95, p99) = if !latency_samples.is_empty() {
            let mut sorted = latency_samples.clone();
            sorted.sort_unstable();
            let sum: u64 = sorted.iter().sum();
            let avg = sum as f64 / sorted.len() as f64;
            let p50 = sorted[sorted.len() / 2] as f64;
            let p95 = sorted[(sorted.len() as f64 * 0.95) as usize] as f64;
            let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)] as f64;
            (avg, p50, p95, p99)
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };

        WorkerMetricsPayload {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            challenged: self.challenged.load(Ordering::Relaxed),
            proxied: self.proxied.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            current_concurrent: self.current_concurrent.load(Ordering::Relaxed),
            peak_concurrent: self.peak_concurrent.load(Ordering::Relaxed),
            avg_latency_ms: avg,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            uptime_secs,
            memory_bytes: 0,  // TODO
            cpu_percent: 0.0, // TODO
            blocked_by_type: blocked_by_type_str,
            per_site,
            static_cache_hits: 0,
            static_cache_misses: 0,
            bandwidth: self.bandwidth.to_payload(),
            serverless_metrics: Vec::new(), // TODO
            health_score: 1.0,
            last_request_at: None,
            active_connections: 0,
            restart_count: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct StaticWorkerMetrics {
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub minifications: AtomicU64,
    pub compressions: AtomicU64,
    pub errors: AtomicU64,
}

impl StaticWorkerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_minification(&self) {
        self.minifications.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_compression(&self) {
        self.compressions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
}
