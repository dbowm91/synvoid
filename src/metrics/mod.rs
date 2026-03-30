use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::process::{SiteMetricsPayload, WorkerMetricsPayload};
use crate::waf::attack_detection::config::AttackType;

pub mod bandwidth;
pub use bandwidth::{
    get_global_bandwidth_tracker, BandwidthPayload, BandwidthProtocol, BandwidthTracker,
    EgressDirection,
};

use std::sync::LazyLock;

const LATENCY_SAMPLE_SIZE: usize = 1000;

static ATTACK_TYPE_COUNTER: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static PROXY_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static PROXY_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static STATIC_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static STATIC_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DROPPED_TLS_RELOAD_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DROPPED_THREAT_LEVEL_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DROPPED_PROCESS_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DROPPED_WORKER_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

#[derive(Debug, Clone)]
pub struct CacheMetrics {
    pub proxy_cache_hits: u64,
    pub proxy_cache_misses: u64,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
}

impl CacheMetrics {
    pub fn proxy_cache_hit_rate(&self) -> f64 {
        let total = self.proxy_cache_hits + self.proxy_cache_misses;
        if total > 0 {
            (self.proxy_cache_hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn static_cache_hit_rate(&self) -> f64 {
        let total = self.static_cache_hits + self.static_cache_misses;
        if total > 0 {
            (self.static_cache_hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
}

pub fn record_proxy_cache_hit() {
    PROXY_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_proxy_cache_miss() {
    PROXY_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_proxy_cache_hits() -> u64 {
    PROXY_CACHE_HITS.load(Ordering::Relaxed)
}

pub fn get_proxy_cache_misses() -> u64 {
    PROXY_CACHE_MISSES.load(Ordering::Relaxed)
}

pub fn record_static_cache_hit() {
    STATIC_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_static_cache_miss() {
    STATIC_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_static_cache_hits() -> u64 {
    STATIC_CACHE_HITS.load(Ordering::Relaxed)
}

pub fn get_static_cache_misses() -> u64 {
    STATIC_CACHE_MISSES.load(Ordering::Relaxed)
}

pub fn record_dropped_tls_reload_event() {
    DROPPED_TLS_RELOAD_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dropped_tls_reload_events() -> u64 {
    DROPPED_TLS_RELOAD_EVENTS.load(Ordering::Relaxed)
}

pub fn record_dropped_threat_level_event() {
    DROPPED_THREAT_LEVEL_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dropped_threat_level_events() -> u64 {
    DROPPED_THREAT_LEVEL_EVENTS.load(Ordering::Relaxed)
}

pub fn record_dropped_process_event() {
    DROPPED_PROCESS_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dropped_process_events() -> u64 {
    DROPPED_PROCESS_EVENTS.load(Ordering::Relaxed)
}

pub fn record_dropped_worker_event() {
    DROPPED_WORKER_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dropped_worker_events() -> u64 {
    DROPPED_WORKER_EVENTS.load(Ordering::Relaxed)
}

pub fn total_dropped_events() -> u64 {
    DROPPED_TLS_RELOAD_EVENTS.load(Ordering::Relaxed)
        + DROPPED_THREAT_LEVEL_EVENTS.load(Ordering::Relaxed)
        + DROPPED_PROCESS_EVENTS.load(Ordering::Relaxed)
        + DROPPED_WORKER_EVENTS.load(Ordering::Relaxed)
}

#[derive(Debug, Clone)]
pub struct DroppedEventCounts {
    pub tls_reload: u64,
    pub threat_level: u64,
    pub process: u64,
    pub worker: u64,
    pub total: u64,
}

pub fn get_dropped_event_counts() -> DroppedEventCounts {
    DroppedEventCounts {
        tls_reload: DROPPED_TLS_RELOAD_EVENTS.load(Ordering::Relaxed),
        threat_level: DROPPED_THREAT_LEVEL_EVENTS.load(Ordering::Relaxed),
        process: DROPPED_PROCESS_EVENTS.load(Ordering::Relaxed),
        worker: DROPPED_WORKER_EVENTS.load(Ordering::Relaxed),
        total: total_dropped_events(),
    }
}

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
    latency_samples: Mutex<Vec<u64>>,
    blocked_by_type: Mutex<HashMap<AttackType, AtomicU64>>,
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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request_start(&self) -> u64 {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let current = self.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        let peak = self.peak_concurrent.load(Ordering::Relaxed);
        if current > peak {
            self.peak_concurrent.store(current, Ordering::Relaxed);
        }
        current
    }

    pub fn record_request_end(&self, latency_ms: u64) {
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.current_concurrent.fetch_sub(1, Ordering::Relaxed);
        self.record_latency(latency_ms);
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

    pub fn is_upstream_healthy(&self) -> bool {
        let successes = self.upstream_successes.load(Ordering::Relaxed);
        let failures = self.upstream_failures.load(Ordering::Relaxed);

        if successes == 0 && failures == 0 {
            return true;
        }

        successes >= 1
    }

    fn record_latency(&self, latency_ms: u64) {
        let mut samples = self.latency_samples.lock();
        if samples.len() < LATENCY_SAMPLE_SIZE {
            samples.push(latency_ms);
        } else {
            let idx = (self.request_count.load(Ordering::Relaxed) as usize) % LATENCY_SAMPLE_SIZE;
            samples[idx] = latency_ms;
        }
    }

    pub fn to_payload(&self, site_id: &str) -> SiteMetricsPayload {
        let count = self.request_count.load(Ordering::Relaxed);
        let avg_latency = if count > 0 {
            self.total_latency_ms.load(Ordering::Relaxed) as f64 / count as f64
        } else {
            0.0
        };

        let samples = self.latency_samples.lock();
        let (p50, p95, p99) = if !samples.is_empty() {
            let mut sorted = samples.clone();
            sorted.sort_unstable();
            let len = sorted.len();
            let p50_idx = ((len as f64 * 0.50) as usize).min(len - 1);
            let p95_idx = ((len as f64 * 0.95) as usize).min(len - 1);
            let p99_idx = ((len as f64 * 0.99) as usize).min(len - 1);
            (
                sorted[p50_idx] as f64,
                sorted[p95_idx] as f64,
                sorted[p99_idx] as f64,
            )
        } else {
            (0.0, 0.0, 0.0)
        };
        drop(samples);

        let blocked_types = self.blocked_by_type.lock();
        let mut blocked_by_type = HashMap::new();
        for (k, v) in blocked_types.iter() {
            blocked_by_type.insert(k.to_string(), v.load(Ordering::Relaxed));
        }

        let (
            bytes_received,
            bytes_sent,
            proxied_bytes_sent,
            proxied_bytes_received,
            mesh_bytes_sent,
            mesh_bytes_received,
        ) = if let Ok(bandwidth) = get_global_bandwidth_tracker() {
            let per_site_bandwidth = bandwidth.get_per_site();
            if let Some(bw) = per_site_bandwidth.get(site_id) {
                (
                    bw.bytes_received,
                    bw.bytes_sent,
                    bw.proxied_bytes_sent,
                    bw.proxied_bytes_received,
                    bw.mesh_bytes_sent,
                    bw.mesh_bytes_received,
                )
            } else {
                (0, 0, 0, 0, 0, 0)
            }
        } else {
            (0, 0, 0, 0, 0, 0)
        };

        SiteMetricsPayload {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            challenged: self.challenged.load(Ordering::Relaxed),
            proxied: self.proxied.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            current_concurrent: self.current_concurrent.load(Ordering::Relaxed),
            peak_concurrent: self.peak_concurrent.load(Ordering::Relaxed),
            avg_latency_ms: avg_latency,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            blocked_by_type,
            upstream_healthy: self.is_upstream_healthy(),
            proxy_cache_hits: 0,
            proxy_cache_misses: 0,
            static_cache_hits: 0,
            static_cache_misses: 0,
            bytes_received,
            bytes_sent,
            proxied_bytes_sent,
            proxied_bytes_received,
            mesh_bytes_sent,
            mesh_bytes_received,
        }
    }
}

pub fn record_attack_type(attack_type: &str) {
    let mut attacks = ATTACK_TYPE_COUNTER.lock();
    attacks
        .entry(attack_type.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn get_attack_type_counts() -> HashMap<String, u64> {
    let attacks = ATTACK_TYPE_COUNTER.lock();
    let mut result = HashMap::new();
    for (k, v) in attacks.iter() {
        result.insert(k.clone(), v.load(Ordering::Relaxed));
    }
    result
}

pub fn reset_attack_type_counts() {
    let mut attacks = ATTACK_TYPE_COUNTER.lock();
    attacks.clear();
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
    latency_samples: Mutex<Vec<u64>>,
    blocked_by_type: Mutex<HashMap<AttackType, AtomicU64>>,
    pub per_site: Mutex<HashMap<String, SiteMetrics>>,
    pub bandwidth: Arc<BandwidthTracker>,
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
        let mut metrics = Self::default();
        if let Some(tracker) = bandwidth::get_global_bandwidth_tracker_or_log() {
            metrics.bandwidth = tracker;
        }
        Arc::new(metrics)
    }

    pub fn record_request_start(&self) -> u64 {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let current = self.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;

        let peak = self.peak_concurrent.load(Ordering::Relaxed);
        if current > peak {
            self.peak_concurrent.store(current, Ordering::Relaxed);
        }

        current
    }

    pub fn record_request_end(&self, latency_ms: u64) {
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.current_concurrent.fetch_sub(1, Ordering::Relaxed);

        self.record_latency(latency_ms);
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

    fn record_latency(&self, latency_ms: u64) {
        let mut samples = self.latency_samples.lock();
        if samples.len() < LATENCY_SAMPLE_SIZE {
            samples.push(latency_ms);
        } else {
            let idx = (self.request_count.load(Ordering::Relaxed) as usize) % LATENCY_SAMPLE_SIZE;
            samples[idx] = latency_ms;
        }
    }

    pub fn to_payload(&self, uptime_secs: u64) -> WorkerMetricsPayload {
        let count = self.request_count.load(Ordering::Relaxed);
        let avg_latency = if count > 0 {
            self.total_latency_ms.load(Ordering::Relaxed) as f64 / count as f64
        } else {
            0.0
        };

        let samples = self.latency_samples.lock();
        let (p50, p95, p99) = if !samples.is_empty() {
            let mut sorted = samples.clone();
            sorted.sort_unstable();
            let len = sorted.len();
            let p50_idx = ((len as f64 * 0.50) as usize).min(len - 1);
            let p95_idx = ((len as f64 * 0.95) as usize).min(len - 1);
            let p99_idx = ((len as f64 * 0.99) as usize).min(len - 1);
            (
                sorted[p50_idx] as f64,
                sorted[p95_idx] as f64,
                sorted[p99_idx] as f64,
            )
        } else {
            (0.0, 0.0, 0.0)
        };

        let blocked_types = self.blocked_by_type.lock();
        let mut blocked_by_type = std::collections::HashMap::new();
        for (k, v) in blocked_types.iter() {
            blocked_by_type.insert(k.to_string(), v.load(Ordering::Relaxed));
        }
        drop(blocked_types);

        let global_attack_types = get_attack_type_counts();
        for (attack_type, count) in global_attack_types {
            *blocked_by_type.entry(attack_type).or_insert(0) += count;
        }

        let per_site = {
            let sites = self.per_site.lock();
            let mut result = std::collections::HashMap::new();
            for (site_id, metrics) in sites.iter() {
                result.insert(site_id.clone(), metrics.to_payload(site_id));
            }
            result
        };

        WorkerMetricsPayload {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            challenged: self.challenged.load(Ordering::Relaxed),
            proxied: self.proxied.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            current_concurrent: self.current_concurrent.load(Ordering::Relaxed),
            peak_concurrent: self.peak_concurrent.load(Ordering::Relaxed),
            avg_latency_ms: avg_latency,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            uptime_secs,
            memory_bytes: 0,
            cpu_percent: 0.0,
            blocked_by_type,
            per_site,
            static_cache_hits: get_static_cache_hits(),
            static_cache_misses: get_static_cache_misses(),
            bandwidth: self.bandwidth.to_payload(),
        }
    }

    pub fn current_concurrent(&self) -> u64 {
        self.current_concurrent.load(Ordering::Relaxed)
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn blocked(&self) -> u64 {
        self.blocked.load(Ordering::Relaxed)
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

    pub fn record_site_request_start(&self, site_id: &str) -> u64 {
        let mut sites = self.per_site.lock();
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
}

#[derive(Debug, Default)]
pub struct StaticWorkerMetrics {
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    minifications: AtomicU64,
    compressions: AtomicU64,
    errors: AtomicU64,
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
