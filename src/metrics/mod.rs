use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::process::{SiteMetricsPayload, WorkerMetricsPayload};
use crate::waf::attack_detection::config::AttackType;

pub mod bandwidth;
pub use bandwidth::{
    get_global_bandwidth_tracker, BandwidthPayload, BandwidthProtocol, BandwidthTracker,
    EgressDirection,
};

use std::sync::LazyLock;

const LATENCY_SAMPLE_SIZE: usize = 1000;
const SERVERLESS_DURATION_SAMPLE_SIZE: usize = 100;

static ATTACK_TYPE_COUNTER: LazyLock<DashMap<String, AtomicU64>> = LazyLock::new(DashMap::new);

static PROXY_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static PROXY_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static STATIC_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static STATIC_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DROPPED_TLS_RELOAD_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DROPPED_THREAT_LEVEL_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DROPPED_PROCESS_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DROPPED_WORKER_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static HONEYPOT_INDICATORS_PUBLISHED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static HONEYPOT_RECORDS_PROCESSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DROPPED_YARA_BROADCASTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DHT_THREAT_LOOKUP_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_THREAT_LOOKUP_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static THREAT_INTEL_DHT_PUBLISH_TOTAL: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_PUBLISH_FAILED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_LOOKUP_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_LOOKUP_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_SYNC_TOTAL: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_SYNC_SUCCESS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_SYNC_FAILED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_SYNC_ADDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static THREAT_INTEL_DHT_SYNC_REMOVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DHT_RECORD_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_REPLICA_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_QUORUM_ACHIEVED_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_QUORUM_FAILED_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DHT_QUERY_LATENCIES: LazyLock<Mutex<Vec<u64>>> = LazyLock::new(|| Mutex::new(Vec::new()));

static DHT_BUCKET_PEER_COUNTS: LazyLock<DashMap<usize, AtomicU64>> = LazyLock::new(DashMap::new);

static DHT_RECORDS_BY_TYPE: LazyLock<DashMap<String, AtomicU64>> = LazyLock::new(DashMap::new);

static DHT_ANNOUNCE_QUEUE_DEPTH: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static DHT_STORE_OPERATIONS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_STORE_FAILURES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_GET_OPERATIONS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_GET_NOT_FOUND: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_ANNOUNCE_SENT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_ANNOUNCE_FAILED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_PEER_DISCOVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_PEER_REMOVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static DHT_PROPAGATION_HOPS: LazyLock<Mutex<Vec<u64>>> = LazyLock::new(|| Mutex::new(Vec::new()));

static SERVERLESS_INVOCATIONS: LazyLock<DashMap<String, AtomicU64>> = LazyLock::new(DashMap::new);

static SERVERLESS_ERRORS: LazyLock<DashMap<String, AtomicU64>> = LazyLock::new(DashMap::new);

static SERVERLESS_DURATIONS: LazyLock<Mutex<HashMap<String, Mutex<Vec<u64>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static SERVERLESS_ACTIVE_INSTANCES: LazyLock<DashMap<String, AtomicU64>> =
    LazyLock::new(DashMap::new);

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

pub fn record_honeypot_indicators_published(count: u64) {
    HONEYPOT_INDICATORS_PUBLISHED.fetch_add(count, Ordering::Relaxed);
}

pub fn get_honeypot_indicators_published() -> u64 {
    HONEYPOT_INDICATORS_PUBLISHED.load(Ordering::Relaxed)
}

pub fn record_honeypot_records_processed(count: u64) {
    HONEYPOT_RECORDS_PROCESSED.fetch_add(count, Ordering::Relaxed);
}

pub fn get_honeypot_records_processed() -> u64 {
    HONEYPOT_RECORDS_PROCESSED.load(Ordering::Relaxed)
}

pub fn record_dropped_yara_broadcast() {
    DROPPED_YARA_BROADCASTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dropped_yara_broadcasts() -> u64 {
    DROPPED_YARA_BROADCASTS.load(Ordering::Relaxed)
}

pub fn record_dht_threat_lookup_hit() {
    DHT_THREAT_LOOKUP_HITS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_dht_threat_lookup_miss() {
    DHT_THREAT_LOOKUP_MISSES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_threat_lookup_hits() -> u64 {
    DHT_THREAT_LOOKUP_HITS.load(Ordering::Relaxed)
}

pub fn get_dht_threat_lookup_misses() -> u64 {
    DHT_THREAT_LOOKUP_MISSES.load(Ordering::Relaxed)
}

pub fn record_threat_intel_dht_publish() {
    THREAT_INTEL_DHT_PUBLISH_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_dht_publish_failed() {
    THREAT_INTEL_DHT_PUBLISH_FAILED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_threat_intel_dht_publish_total() -> u64 {
    THREAT_INTEL_DHT_PUBLISH_TOTAL.load(Ordering::Relaxed)
}

pub fn get_threat_intel_dht_publish_failed() -> u64 {
    THREAT_INTEL_DHT_PUBLISH_FAILED.load(Ordering::Relaxed)
}

pub fn record_threat_intel_dht_lookup_hit() {
    THREAT_INTEL_DHT_LOOKUP_HITS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_dht_lookup_miss() {
    THREAT_INTEL_DHT_LOOKUP_MISSES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_threat_intel_dht_lookup_hits() -> u64 {
    THREAT_INTEL_DHT_LOOKUP_HITS.load(Ordering::Relaxed)
}

pub fn get_threat_intel_dht_lookup_misses() -> u64 {
    THREAT_INTEL_DHT_LOOKUP_MISSES.load(Ordering::Relaxed)
}

pub fn record_threat_intel_dht_sync() {
    THREAT_INTEL_DHT_SYNC_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_dht_sync_success() {
    THREAT_INTEL_DHT_SYNC_SUCCESS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_dht_sync_failed() {
    THREAT_INTEL_DHT_SYNC_FAILED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_dht_sync_added(count: u64) {
    THREAT_INTEL_DHT_SYNC_ADDED.fetch_add(count, Ordering::Relaxed);
}

pub fn record_threat_intel_dht_sync_removed(count: u64) {
    THREAT_INTEL_DHT_SYNC_REMOVED.fetch_add(count, Ordering::Relaxed);
}

pub fn get_threat_intel_dht_sync_total() -> u64 {
    THREAT_INTEL_DHT_SYNC_TOTAL.load(Ordering::Relaxed)
}

pub fn get_threat_intel_dht_sync_success() -> u64 {
    THREAT_INTEL_DHT_SYNC_SUCCESS.load(Ordering::Relaxed)
}

pub fn get_threat_intel_dht_sync_failed() -> u64 {
    THREAT_INTEL_DHT_SYNC_FAILED.load(Ordering::Relaxed)
}

pub fn get_threat_intel_dht_sync_added() -> u64 {
    THREAT_INTEL_DHT_SYNC_ADDED.load(Ordering::Relaxed)
}

pub fn get_threat_intel_dht_sync_removed() -> u64 {
    THREAT_INTEL_DHT_SYNC_REMOVED.load(Ordering::Relaxed)
}

pub fn record_dht_quorum_success() {
    DHT_QUORUM_ACHIEVED_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn record_dht_quorum_failure() {
    DHT_QUORUM_FAILED_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_quorum_achieved_count() -> u64 {
    DHT_QUORUM_ACHIEVED_COUNT.load(Ordering::Relaxed)
}

pub fn get_dht_quorum_failed_count() -> u64 {
    DHT_QUORUM_FAILED_COUNT.load(Ordering::Relaxed)
}

pub fn record_dht_query_latency(latency_ms: u64) {
    let mut latencies = DHT_QUERY_LATENCIES.lock();
    latencies.push(latency_ms);
    if latencies.len() > LATENCY_SAMPLE_SIZE {
        latencies.remove(0);
    }
}

pub fn get_dht_average_query_latency_ms() -> f64 {
    let latencies = DHT_QUERY_LATENCIES.lock();
    if latencies.is_empty() {
        return 0.0;
    }
    let sum: u64 = latencies.iter().sum();
    sum as f64 / latencies.len() as f64
}

pub fn record_dht_record_count(count: u64) {
    DHT_RECORD_COUNT.store(count, Ordering::Relaxed);
}

pub fn get_dht_record_count() -> u64 {
    DHT_RECORD_COUNT.load(Ordering::Relaxed)
}

pub fn record_dht_replica_count(count: u64) {
    DHT_REPLICA_COUNT.store(count, Ordering::Relaxed);
}

pub fn get_dht_replica_count() -> u64 {
    DHT_REPLICA_COUNT.load(Ordering::Relaxed)
}

pub fn record_dht_bucket_peers(bucket_index: usize, count: u64) {
    if let Some(counter) = DHT_BUCKET_PEER_COUNTS.get(&bucket_index) {
        counter.store(count, Ordering::Relaxed);
    } else {
        DHT_BUCKET_PEER_COUNTS.insert(bucket_index, AtomicU64::new(count));
    }
}

pub fn get_dht_bucket_peers(bucket_index: usize) -> u64 {
    DHT_BUCKET_PEER_COUNTS
        .get(&bucket_index)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn get_all_dht_bucket_peers() -> HashMap<usize, u64> {
    DHT_BUCKET_PEER_COUNTS
        .iter()
        .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
        .collect()
}

pub fn record_dht_record_by_type(record_type: &str, count: u64) {
    let counter = DHT_RECORDS_BY_TYPE
        .entry(record_type.to_string())
        .or_insert_with(|| AtomicU64::new(0));
    counter.store(count, Ordering::Relaxed);
}

pub fn increment_dht_records_by_type(record_type: &str) {
    if let Some(counter) = DHT_RECORDS_BY_TYPE.get(record_type) {
        counter.fetch_add(1, Ordering::Relaxed);
    } else {
        DHT_RECORDS_BY_TYPE.insert(record_type.to_string(), AtomicU64::new(1));
    }
}

pub fn get_dht_records_by_type(record_type: &str) -> u64 {
    DHT_RECORDS_BY_TYPE
        .get(record_type)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn get_all_dht_records_by_type() -> HashMap<String, u64> {
    DHT_RECORDS_BY_TYPE
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
        .collect()
}

pub fn record_dht_announce_queue_depth(depth: usize) {
    DHT_ANNOUNCE_QUEUE_DEPTH.store(depth as u64, Ordering::Relaxed);
}

pub fn get_dht_announce_queue_depth() -> u64 {
    DHT_ANNOUNCE_QUEUE_DEPTH.load(Ordering::Relaxed)
}

pub fn record_dht_store_operation(success: bool) {
    DHT_STORE_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    if !success {
        DHT_STORE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn get_dht_store_operations() -> u64 {
    DHT_STORE_OPERATIONS.load(Ordering::Relaxed)
}

pub fn get_dht_store_failures() -> u64 {
    DHT_STORE_FAILURES.load(Ordering::Relaxed)
}

pub fn record_dht_get_operation(found: bool) {
    DHT_GET_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    if !found {
        DHT_GET_NOT_FOUND.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn get_dht_get_operations() -> u64 {
    DHT_GET_OPERATIONS.load(Ordering::Relaxed)
}

pub fn get_dht_get_not_found() -> u64 {
    DHT_GET_NOT_FOUND.load(Ordering::Relaxed)
}

pub fn record_dht_announce_sent() {
    DHT_ANNOUNCE_SENT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_announce_sent() -> u64 {
    DHT_ANNOUNCE_SENT.load(Ordering::Relaxed)
}

pub fn record_dht_announce_failed() {
    DHT_ANNOUNCE_FAILED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_announce_failed() -> u64 {
    DHT_ANNOUNCE_FAILED.load(Ordering::Relaxed)
}

pub fn record_dht_peer_discovered() {
    DHT_PEER_DISCOVERED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_peer_discovered() -> u64 {
    DHT_PEER_DISCOVERED.load(Ordering::Relaxed)
}

pub fn record_dht_peer_removed() {
    DHT_PEER_REMOVED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_peer_removed() -> u64 {
    DHT_PEER_REMOVED.load(Ordering::Relaxed)
}

pub fn record_dht_propagation_hop(hop_count: u64) {
    let mut hops = DHT_PROPAGATION_HOPS.lock();
    hops.push(hop_count);
    if hops.len() > LATENCY_SAMPLE_SIZE {
        hops.remove(0);
    }
}

pub fn get_dht_average_propagation_hops() -> f64 {
    let hops = DHT_PROPAGATION_HOPS.lock();
    if hops.is_empty() {
        return 0.0;
    }
    let sum: u64 = hops.iter().sum();
    sum as f64 / hops.len() as f64
}

pub fn total_dropped_events() -> u64 {
    DROPPED_TLS_RELOAD_EVENTS.load(Ordering::Relaxed)
        + DROPPED_THREAT_LEVEL_EVENTS.load(Ordering::Relaxed)
        + DROPPED_PROCESS_EVENTS.load(Ordering::Relaxed)
        + DROPPED_WORKER_EVENTS.load(Ordering::Relaxed)
        + DROPPED_YARA_BROADCASTS.load(Ordering::Relaxed)
}

#[derive(Debug, Clone)]
pub struct DroppedEventCounts {
    pub tls_reload: u64,
    pub threat_level: u64,
    pub process: u64,
    pub worker: u64,
    pub yara_broadcast: u64,
    pub total: u64,
}

pub fn get_dropped_event_counts() -> DroppedEventCounts {
    DroppedEventCounts {
        tls_reload: DROPPED_TLS_RELOAD_EVENTS.load(Ordering::Relaxed),
        threat_level: DROPPED_THREAT_LEVEL_EVENTS.load(Ordering::Relaxed),
        process: DROPPED_PROCESS_EVENTS.load(Ordering::Relaxed),
        worker: DROPPED_WORKER_EVENTS.load(Ordering::Relaxed),
        yara_broadcast: DROPPED_YARA_BROADCASTS.load(Ordering::Relaxed),
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
        self.current_concurrent
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
            .ok();
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
    let counter = ATTACK_TYPE_COUNTER
        .entry(attack_type.to_string())
        .or_insert_with(|| AtomicU64::new(0));
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn get_attack_type_counts() -> HashMap<String, u64> {
    let mut result = HashMap::new();
    for entry in ATTACK_TYPE_COUNTER.iter() {
        result.insert(entry.key().clone(), entry.value().load(Ordering::Relaxed));
    }
    result
}

pub fn reset_attack_type_counts() {
    ATTACK_TYPE_COUNTER.clear();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessMetrics {
    pub function_name: String,
    pub invocations_total: u64,
    pub errors_total: u64,
    pub avg_duration_ms: f64,
    pub active_instances: usize,
}

pub fn record_serverless_invocation(function: &str, status: &str) {
    let counter = SERVERLESS_INVOCATIONS
        .entry(function.to_string())
        .or_insert_with(|| AtomicU64::new(0));
    counter.fetch_add(1, Ordering::Relaxed);

    if status == "error" {
        let error_counter = SERVERLESS_ERRORS
            .entry(function.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        error_counter.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_serverless_duration(function: &str, duration_ms: u64) {
    let mut durations = SERVERLESS_DURATIONS.lock();
    let samples = durations
        .entry(function.to_string())
        .or_insert_with(|| Mutex::new(Vec::with_capacity(SERVERLESS_DURATION_SAMPLE_SIZE)));
    let mut samples_guard = samples.lock();
    if samples_guard.len() < SERVERLESS_DURATION_SAMPLE_SIZE {
        samples_guard.push(duration_ms);
    } else {
        let idx = samples_guard.len() % SERVERLESS_DURATION_SAMPLE_SIZE;
        samples_guard[idx] = duration_ms;
    }
}

pub fn record_serverless_active_instances(function: &str, count: usize) {
    let counter = SERVERLESS_ACTIVE_INSTANCES
        .entry(function.to_string())
        .or_insert_with(|| AtomicU64::new(0));
    counter.store(count as u64, Ordering::Relaxed);
}

pub fn get_serverless_invocation_count(function: &str) -> u64 {
    SERVERLESS_INVOCATIONS
        .get(function)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn get_serverless_error_count(function: &str) -> u64 {
    SERVERLESS_ERRORS
        .get(function)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn get_serverless_duration_avg(function: &str) -> f64 {
    let durations = SERVERLESS_DURATIONS.lock();
    if let Some(samples) = durations.get(function) {
        let samples_guard = samples.lock();
        if !samples_guard.is_empty() {
            let sum: u64 = samples_guard.iter().sum();
            return sum as f64 / samples_guard.len() as f64;
        }
    }
    0.0
}

pub fn get_serverless_active_instances(function: &str) -> usize {
    SERVERLESS_ACTIVE_INSTANCES
        .get(function)
        .map(|c| c.load(Ordering::Relaxed) as usize)
        .unwrap_or(0)
}

pub fn get_all_serverless_metrics() -> Vec<ServerlessMetrics> {
    let durations = SERVERLESS_DURATIONS.lock();

    let mut functions: Vec<String> = SERVERLESS_INVOCATIONS
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    for entry in SERVERLESS_ERRORS.iter() {
        let func = entry.key();
        if !functions.contains(func) {
            functions.push(func.clone());
        }
    }
    for func in durations.keys() {
        if !functions.contains(func) {
            functions.push(func.clone());
        }
    }
    for entry in SERVERLESS_ACTIVE_INSTANCES.iter() {
        let func = entry.key();
        if !functions.contains(func) {
            functions.push(func.clone());
        }
    }

    functions
        .into_iter()
        .map(|func| {
            let invocations_total = SERVERLESS_INVOCATIONS
                .get(&func)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            let errors_total = SERVERLESS_ERRORS
                .get(&func)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            let avg_duration_ms = if let Some(samples) = durations.get(&func) {
                let samples_guard = samples.lock();
                if !samples_guard.is_empty() {
                    let sum: u64 = samples_guard.iter().sum();
                    sum as f64 / samples_guard.len() as f64
                } else {
                    0.0
                }
            } else {
                0.0
            };
            let active_instances = SERVERLESS_ACTIVE_INSTANCES
                .get(&func)
                .map(|c| c.load(Ordering::Relaxed) as usize)
                .unwrap_or(0);

            ServerlessMetrics {
                function_name: func,
                invocations_total,
                errors_total,
                avg_duration_ms,
                active_instances,
            }
        })
        .collect()
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
        self.current_concurrent
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
            .ok();

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
            serverless_metrics: get_all_serverless_metrics(),
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
