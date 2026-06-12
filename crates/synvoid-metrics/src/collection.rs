use crate::payloads::{DroppedEventCounts, ServerlessMetrics};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

pub(crate) const SERVERLESS_DURATION_SAMPLE_SIZE: usize = 100;

pub(crate) static ATTACK_TYPE_COUNTER: LazyLock<DashMap<String, AtomicU64>> =
    LazyLock::new(DashMap::new);

pub(crate) static PROXY_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static PROXY_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub(crate) static DROPPED_TLS_RELOAD_EVENTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_THREAT_LEVEL_EVENTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_PROCESS_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_WORKER_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DROPPED_YARA_BROADCASTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static ACTIVE_STALLED_REQUESTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static STALL_REJECTED_CONCURRENCY_CAP: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static STALL_TIMEOUTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub(crate) static TLS_PASSTHROUGH_REQUESTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static TLS_PASSTHROUGH_WAF_BYPASSED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static HONEYPOT_INDICATORS_PUBLISHED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static HONEYPOT_RECORDS_PROCESSED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static HONEYPOT_HTTP_TRAPS_HIT: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static PORT_HONEYPOT_CONNECTIONS_CAPTURED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static DHT_THREAT_LOOKUP_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_THREAT_LOOKUP_MISSES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static THREAT_INTEL_DHT_PUBLISH_TOTAL: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_PUBLISH_FAILED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_LOOKUP_HITS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_LOOKUP_MISSES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_SYNC_TOTAL: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_SYNC_SUCCESS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_SYNC_FAILED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_SYNC_ADDED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_DHT_SYNC_REMOVED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static THREAT_INTEL_POLICY_SHADOW_ACTIONABLE: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_ADVISORY_ONLY: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_NOT_ACTIONABLE: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_DEFERRED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_NOT_CONFIGURED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_RAW_DISAGREEMENT: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_CANONICAL_UNAVAILABLE: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static THREAT_INTEL_POLICY_SHADOW_ADVISORY_MISSING: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static BEHAVIORAL_FINGERPRINT_DHT_PUBLISH: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static BEHAVIORAL_FINGERPRINT_RECEIVED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static BEHAVIORAL_FINGERPRINT_MATCH: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static DHT_RECORD_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_REPLICA_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_QUORUM_ACHIEVED_COUNT: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_QUORUM_FAILED_COUNT: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_QUORUM_REGIONAL_COUNT: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_QUORUM_FULL_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_VERIFICATION_FAILURES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_RAFT_WRITE_FAILURES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static DHT_QUERY_LATENCIES: LazyLock<Mutex<VecDeque<u64>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));
pub(crate) static HTTP_REQUEST_LATENCIES: LazyLock<Mutex<VecDeque<u64>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));
pub(crate) static WAF_CHECK_TIMINGS: LazyLock<Mutex<VecDeque<u64>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

pub(crate) static DHT_BUCKET_PEER_COUNTS: LazyLock<DashMap<usize, AtomicU64>> =
    LazyLock::new(DashMap::new);
pub(crate) static DHT_RECORDS_BY_TYPE: LazyLock<DashMap<String, AtomicU64>> =
    LazyLock::new(DashMap::new);

pub(crate) static DHT_ANNOUNCE_QUEUE_DEPTH: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_STORE_OPERATIONS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_STORE_FAILURES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_RATE_LIMITED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_GET_OPERATIONS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_GET_NOT_FOUND: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_ANNOUNCE_SENT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_ANNOUNCE_FAILED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_PEER_DISCOVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_PEER_REMOVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub(crate) static DHT_PROPAGATION_HOPS: LazyLock<Mutex<VecDeque<u64>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

pub(crate) static GLOBAL_NODE_LIVENESS_COUNT: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));
pub(crate) static GLOBAL_NODE_QUORUM_LOST_EVENTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub(crate) static SERVERLESS_INVOCATIONS: LazyLock<DashMap<String, AtomicU64>> =
    LazyLock::new(DashMap::new);
pub(crate) static SERVERLESS_ERRORS: LazyLock<DashMap<String, AtomicU64>> =
    LazyLock::new(DashMap::new);
pub(crate) static SERVERLESS_DURATIONS: LazyLock<Mutex<HashMap<String, Mutex<Vec<u64>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub(crate) static SERVERLESS_ACTIVE_INSTANCES: LazyLock<DashMap<String, AtomicU64>> =
    LazyLock::new(DashMap::new);

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

pub(crate) fn release_stall_permit() {
    ACTIVE_STALLED_REQUESTS.fetch_sub(1, Ordering::Release);
}

pub fn record_stall_timeout() {
    STALL_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_stall_rejected() {
    STALL_REJECTED_CONCURRENCY_CAP.fetch_add(1, Ordering::Relaxed);
}

pub fn get_active_stalled_requests() -> u64 {
    ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed)
}

pub fn get_stall_rejected_count() -> u64 {
    STALL_REJECTED_CONCURRENCY_CAP.load(Ordering::Relaxed)
}

pub fn get_stall_timeouts() -> u64 {
    STALL_TIMEOUTS.load(Ordering::Relaxed)
}

/// RAII guard for a stall concurrency slot.
///
/// Increments `ACTIVE_STALLED_REQUESTS` on creation and decrements on drop,
/// guaranteeing the counter is released even if the owning task is cancelled
/// mid-sleep. This prevents zombie stalls from permanently inflating the
/// concurrency cap.
pub struct StallPermit {
    _active: bool,
}

impl StallPermit {
    /// Try to acquire a stall permit. Returns `Some(StallPermit)` if below
    /// `max_stalled`, or `None` (after recording the rejection metric) if
    /// the cap has been reached.
    ///
    /// When `max_stalled` is 0, acquisition always fails.
    pub fn try_new(max_stalled: u32) -> Option<Self> {
        if max_stalled == 0 {
            record_stall_rejected();
            return None;
        }
        let max = max_stalled as u64;
        ACTIVE_STALLED_REQUESTS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= max {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .map(|_| StallPermit { _active: true })
            .ok()
            .or_else(|| {
                record_stall_rejected();
                None
            })
    }
}

impl Drop for StallPermit {
    fn drop(&mut self) {
        release_stall_permit();
    }
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

pub fn record_tls_passthrough_request() {
    TLS_PASSTHROUGH_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_tls_passthrough_requests() -> u64 {
    TLS_PASSTHROUGH_REQUESTS.load(Ordering::Relaxed)
}

pub fn record_tls_passthrough_waf_bypassed() {
    TLS_PASSTHROUGH_WAF_BYPASSED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_tls_passthrough_waf_bypassed() -> u64 {
    TLS_PASSTHROUGH_WAF_BYPASSED.load(Ordering::Relaxed)
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

pub fn record_honeypot_http_traps_hit() {
    HONEYPOT_HTTP_TRAPS_HIT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_honeypot_http_traps_hit() -> u64 {
    HONEYPOT_HTTP_TRAPS_HIT.load(Ordering::Relaxed)
}

pub fn record_port_honeypot_connections_captured() {
    PORT_HONEYPOT_CONNECTIONS_CAPTURED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_port_honeypot_connections_captured() -> u64 {
    PORT_HONEYPOT_CONNECTIONS_CAPTURED.load(Ordering::Relaxed)
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

pub fn record_threat_intel_policy_shadow_actionable() {
    THREAT_INTEL_POLICY_SHADOW_ACTIONABLE.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_advisory_only() {
    THREAT_INTEL_POLICY_SHADOW_ADVISORY_ONLY.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_not_actionable() {
    THREAT_INTEL_POLICY_SHADOW_NOT_ACTIONABLE.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_deferred() {
    THREAT_INTEL_POLICY_SHADOW_DEFERRED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_not_configured() {
    THREAT_INTEL_POLICY_SHADOW_NOT_CONFIGURED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_raw_disagreement() {
    THREAT_INTEL_POLICY_SHADOW_RAW_DISAGREEMENT.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_canonical_unavailable() {
    THREAT_INTEL_POLICY_SHADOW_CANONICAL_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
}

pub fn record_threat_intel_policy_shadow_advisory_missing() {
    THREAT_INTEL_POLICY_SHADOW_ADVISORY_MISSING.fetch_add(1, Ordering::Relaxed);
}

pub fn get_threat_intel_policy_shadow_actionable() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_ACTIONABLE.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_advisory_only() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_ADVISORY_ONLY.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_not_actionable() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_NOT_ACTIONABLE.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_deferred() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_DEFERRED.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_not_configured() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_NOT_CONFIGURED.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_raw_disagreement() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_RAW_DISAGREEMENT.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_canonical_unavailable() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_CANONICAL_UNAVAILABLE.load(Ordering::Relaxed)
}

pub fn get_threat_intel_policy_shadow_advisory_missing() -> u64 {
    THREAT_INTEL_POLICY_SHADOW_ADVISORY_MISSING.load(Ordering::Relaxed)
}

pub fn record_behavioral_fingerprint_dht_publish() {
    BEHAVIORAL_FINGERPRINT_DHT_PUBLISH.fetch_add(1, Ordering::Relaxed);
}

pub fn record_behavioral_fingerprint_received() {
    BEHAVIORAL_FINGERPRINT_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_behavioral_fingerprint_match() {
    BEHAVIORAL_FINGERPRINT_MATCH.fetch_add(1, Ordering::Relaxed);
}

pub fn get_behavioral_fingerprint_dht_publish() -> u64 {
    BEHAVIORAL_FINGERPRINT_DHT_PUBLISH.load(Ordering::Relaxed)
}

pub fn get_behavioral_fingerprint_received() -> u64 {
    BEHAVIORAL_FINGERPRINT_RECEIVED.load(Ordering::Relaxed)
}

pub fn get_behavioral_fingerprint_match() -> u64 {
    BEHAVIORAL_FINGERPRINT_MATCH.load(Ordering::Relaxed)
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

pub fn record_dht_quorum_regional() {
    DHT_QUORUM_REGIONAL_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn record_dht_quorum_full() {
    DHT_QUORUM_FULL_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_quorum_regional_count() -> u64 {
    DHT_QUORUM_REGIONAL_COUNT.load(Ordering::Relaxed)
}

pub fn get_dht_quorum_full_count() -> u64 {
    DHT_QUORUM_FULL_COUNT.load(Ordering::Relaxed)
}

pub fn record_dht_verification_failure() {
    DHT_VERIFICATION_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_verification_failures() -> u64 {
    DHT_VERIFICATION_FAILURES.load(Ordering::Relaxed)
}

pub fn record_dht_raft_write_failure() {
    DHT_RAFT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_raft_write_failures() -> u64 {
    DHT_RAFT_WRITE_FAILURES.load(Ordering::Relaxed)
}

pub fn record_dht_query_latency(latency_ms: u64) {
    let mut latencies = DHT_QUERY_LATENCIES.lock();
    if latencies.len() < crate::LATENCY_SAMPLE_SIZE {
        latencies.push_back(latency_ms);
    } else {
        latencies.pop_front();
        latencies.push_back(latency_ms);
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

pub fn record_http_request_latency(latency_ms: u64) {
    let mut latencies = HTTP_REQUEST_LATENCIES.lock();
    if latencies.len() < crate::LATENCY_SAMPLE_SIZE {
        latencies.push_back(latency_ms);
    } else {
        latencies.pop_front();
        latencies.push_back(latency_ms);
    }
}

pub fn get_http_request_latencies() -> Vec<u64> {
    let latencies = HTTP_REQUEST_LATENCIES.lock();
    latencies.iter().cloned().collect()
}

pub fn record_waf_check_timing(_check_type: &str, latency_ms: u64) {
    let mut timings = WAF_CHECK_TIMINGS.lock();
    if timings.len() < crate::LATENCY_SAMPLE_SIZE {
        timings.push_back(latency_ms);
    } else {
        timings.pop_front();
        timings.push_back(latency_ms);
    }
}

pub fn get_waf_check_timings() -> Vec<u64> {
    let timings = WAF_CHECK_TIMINGS.lock();
    timings.iter().cloned().collect()
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
    let counter = DHT_BUCKET_PEER_COUNTS
        .entry(bucket_index)
        .or_insert_with(|| AtomicU64::new(0));
    counter.store(count, Ordering::Relaxed);
}

pub fn get_dht_bucket_peers(bucket_index: usize) -> u64 {
    DHT_BUCKET_PEER_COUNTS
        .get(&bucket_index)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn get_all_dht_bucket_peers() -> HashMap<usize, u64> {
    let mut result = HashMap::new();
    for entry in DHT_BUCKET_PEER_COUNTS.iter() {
        result.insert(*entry.key(), entry.value().load(Ordering::Relaxed));
    }
    result
}

pub fn record_dht_record_by_type(record_type: &str, count: u64) {
    let counter = DHT_RECORDS_BY_TYPE
        .entry(record_type.to_string())
        .or_insert_with(|| AtomicU64::new(0));
    counter.store(count, Ordering::Relaxed);
}

pub fn increment_dht_records_by_type(record_type: &str) {
    let counter = DHT_RECORDS_BY_TYPE
        .entry(record_type.to_string())
        .or_insert_with(|| AtomicU64::new(0));
    counter.fetch_add(1, Ordering::Relaxed);
}

pub fn get_dht_records_by_type(record_type: &str) -> u64 {
    DHT_RECORDS_BY_TYPE
        .get(record_type)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

pub fn get_all_dht_records_by_type() -> HashMap<String, u64> {
    let mut result = HashMap::new();
    for entry in DHT_RECORDS_BY_TYPE.iter() {
        result.insert(entry.key().clone(), entry.value().load(Ordering::Relaxed));
    }
    result
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

pub fn record_dht_store_rate_limited() {
    DHT_RATE_LIMITED.fetch_add(1, Ordering::Relaxed);
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
    if hops.len() < crate::LATENCY_SAMPLE_SIZE {
        hops.push_back(hop_count);
    } else {
        hops.pop_front();
        hops.push_back(hop_count);
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

pub fn record_global_node_liveness_count(count: u64) {
    GLOBAL_NODE_LIVENESS_COUNT.store(count, Ordering::Relaxed);
}

pub fn get_global_node_liveness_count() -> u64 {
    GLOBAL_NODE_LIVENESS_COUNT.load(Ordering::Relaxed)
}

pub fn record_global_node_quorum_lost() {
    GLOBAL_NODE_QUORUM_LOST_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_global_node_quorum_lost_events() -> u64 {
    GLOBAL_NODE_QUORUM_LOST_EVENTS.load(Ordering::Relaxed)
}

pub fn total_dropped_events() -> u64 {
    DROPPED_TLS_RELOAD_EVENTS.load(Ordering::Relaxed)
        + DROPPED_THREAT_LEVEL_EVENTS.load(Ordering::Relaxed)
        + DROPPED_PROCESS_EVENTS.load(Ordering::Relaxed)
        + DROPPED_WORKER_EVENTS.load(Ordering::Relaxed)
        + DROPPED_YARA_BROADCASTS.load(Ordering::Relaxed)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stall_permit_rejects_when_limit_zero() {
        let before = STALL_REJECTED_CONCURRENCY_CAP.load(Ordering::Relaxed);
        assert!(StallPermit::try_new(0).is_none());
        assert_eq!(
            STALL_REJECTED_CONCURRENCY_CAP.load(Ordering::Relaxed),
            before + 1
        );
    }

    #[test]
    fn stall_permit_acquires_below_limit() {
        let before = ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed);
        let permit = StallPermit::try_new(10);
        assert!(permit.is_some());
        assert_eq!(ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed), before + 1);
        drop(permit);
        assert_eq!(ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed), before);
    }

    #[test]
    fn stall_permit_rejects_at_limit() {
        let mut permits = Vec::new();
        for _ in 0..5 {
            permits.push(StallPermit::try_new(5).unwrap());
        }
        assert!(StallPermit::try_new(5).is_none());
        drop(permits);
    }

    #[test]
    fn stall_permit_drop_releases_active_count() {
        let before = ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed);
        {
            let _permit = StallPermit::try_new(u32::MAX).unwrap();
            assert_eq!(ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed), before + 1);
        }
        assert_eq!(ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed), before);
    }

    #[test]
    fn stall_permit_strict_atomic_cap_under_concurrency() {
        use std::sync::Arc;
        use std::thread;

        let cap: u32 = 10;
        let before = ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed);
        let permits = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let permits = permits.clone();
                thread::spawn(move || {
                    if let Some(p) = StallPermit::try_new(cap) {
                        permits.lock().push(p);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let acquired = permits.lock().len();
        assert!(
            acquired <= cap as usize,
            "acquired {} permits but cap is {}",
            acquired,
            cap
        );
        assert_eq!(
            ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed),
            before + acquired as u64
        );
        drop(permits);
    }

    #[test]
    fn stall_timeout_metric_increments_separately() {
        let before = STALL_TIMEOUTS.load(Ordering::Relaxed);
        record_stall_timeout();
        assert_eq!(STALL_TIMEOUTS.load(Ordering::Relaxed), before + 1);
    }

    #[test]
    fn release_stall_permit_does_not_increment_timeout() {
        let timeout_before = STALL_TIMEOUTS.load(Ordering::Relaxed);
        let active_before = ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed);
        {
            let _permit = StallPermit::try_new(u32::MAX).unwrap();
            assert_eq!(
                ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed),
                active_before + 1
            );
        }
        // Drop only releases, does not record timeout
        assert_eq!(
            STALL_TIMEOUTS.load(Ordering::Relaxed),
            timeout_before,
            "drop must not increment timeout counter"
        );
        assert_eq!(
            ACTIVE_STALLED_REQUESTS.load(Ordering::Relaxed),
            active_before
        );
    }
}
