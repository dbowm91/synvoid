use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

/// DNS metrics collector with atomic counters and labeled `metrics::counter!` emissions.
///
/// Counters fall into three categories:
/// - **Atomic only**: high-frequency counters used internally for aggregation.
/// - **Atomic + metrics crate**: counters that also emit to the `metrics` facade for
///   external scrapers (Prometheus, Datadog, etc.).
/// - **Labeled**: counters emitted with a single low-cardinality label (transport,
///   operation type, response code) via `metrics::counter!`.
///
/// High-cardinality maps (per-domain, per-query-type) are intentionally excluded.
pub struct DnsMetrics {
    queries_received: AtomicU64,
    queries_blocked: AtomicU64,
    queries_validated: AtomicU64,
    responses_sent: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_stale_hits: AtomicU64,
    cache_negative_hits: AtomicU64,
    cache_invalidations: AtomicU64,
    cache_poisoned_rejections: AtomicU64,
    cache_insertions: AtomicU64,
    cache_size_rejections: AtomicU64,
    dnssec_queries: AtomicU64,
    dnssec_signed_responses: AtomicU64,
    rate_limited_queries: AtomicU64,
    rrl_limited_responses: AtomicU64,
    malformed_queries: AtomicU64,
    nxdomain_responses: AtomicU64,
    encode_failures: AtomicU64,
    tcp_connections: AtomicUsize,
    active_tcp_connections: AtomicUsize,
    query_latencies: RwLock<Vec<u64>>,
    firewall_queries_allowed: AtomicU64,
    firewall_queries_blocked: AtomicU64,
    bailiwick_violations: AtomicU64,

    recursive_queries: AtomicU64,
    recursive_cache_hits: AtomicU64,
    recursive_cache_misses: AtomicU64,
    recursive_upstream_forwards: AtomicU64,
    recursive_upstream_failures: AtomicU64,
    recursive_circuit_breaker_opens: AtomicU64,
    recursive_circuit_breaker_closes: AtomicU64,

    transport_queries: RwLock<HashMap<String, AtomicU64>>,
    transport_errors: RwLock<HashMap<String, AtomicU64>>,

    operation_counts: RwLock<HashMap<String, AtomicU64>>,

    zones_loaded: AtomicU64,
    zone_reload_successes: AtomicU64,
    zone_reload_failures: AtomicU64,

    dnssec_key_rotations: AtomicU64,
    dnssec_signing_failures: AtomicU64,

    update_accepted: AtomicU64,
    update_rejected: AtomicU64,
    notify_sent: AtomicU64,
    notify_received: AtomicU64,
    axfr_accepted: AtomicU64,
    axfr_rejected: AtomicU64,
    ixfr_accepted: AtomicU64,
    ixfr_rejected: AtomicU64,

    last_reset: Instant,
}

impl DnsMetrics {
    pub fn new() -> Self {
        Self {
            queries_received: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            queries_validated: AtomicU64::new(0),
            responses_sent: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_stale_hits: AtomicU64::new(0),
            cache_negative_hits: AtomicU64::new(0),
            cache_invalidations: AtomicU64::new(0),
            cache_poisoned_rejections: AtomicU64::new(0),
            cache_insertions: AtomicU64::new(0),
            cache_size_rejections: AtomicU64::new(0),
            dnssec_queries: AtomicU64::new(0),
            dnssec_signed_responses: AtomicU64::new(0),
            rate_limited_queries: AtomicU64::new(0),
            rrl_limited_responses: AtomicU64::new(0),
            malformed_queries: AtomicU64::new(0),
            nxdomain_responses: AtomicU64::new(0),
            encode_failures: AtomicU64::new(0),
            tcp_connections: AtomicUsize::new(0),
            active_tcp_connections: AtomicUsize::new(0),
            query_latencies: RwLock::new(Vec::new()),
            firewall_queries_allowed: AtomicU64::new(0),
            firewall_queries_blocked: AtomicU64::new(0),
            bailiwick_violations: AtomicU64::new(0),
            recursive_queries: AtomicU64::new(0),
            recursive_cache_hits: AtomicU64::new(0),
            recursive_cache_misses: AtomicU64::new(0),
            recursive_upstream_forwards: AtomicU64::new(0),
            recursive_upstream_failures: AtomicU64::new(0),
            recursive_circuit_breaker_opens: AtomicU64::new(0),
            recursive_circuit_breaker_closes: AtomicU64::new(0),
            transport_queries: RwLock::new(HashMap::new()),
            transport_errors: RwLock::new(HashMap::new()),
            operation_counts: RwLock::new(HashMap::new()),
            zones_loaded: AtomicU64::new(0),
            zone_reload_successes: AtomicU64::new(0),
            zone_reload_failures: AtomicU64::new(0),
            dnssec_key_rotations: AtomicU64::new(0),
            dnssec_signing_failures: AtomicU64::new(0),
            update_accepted: AtomicU64::new(0),
            update_rejected: AtomicU64::new(0),
            notify_sent: AtomicU64::new(0),
            notify_received: AtomicU64::new(0),
            axfr_accepted: AtomicU64::new(0),
            axfr_rejected: AtomicU64::new(0),
            ixfr_accepted: AtomicU64::new(0),
            ixfr_rejected: AtomicU64::new(0),
            last_reset: Instant::now(),
        }
    }

    /// Record an incoming DNS query. Emits `dns_queries_received`.
    pub fn record_query_received(&self) {
        self.queries_received.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_queries_received").increment(1);
    }

    /// Record a blocked DNS query. Emits `dns_queries_blocked`.
    pub fn record_query_blocked(&self, _domain: &str) {
        self.queries_blocked.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_queries_blocked").increment(1);
    }

    /// Record a validated DNS query. Emits `dns_queries_validated`.
    pub fn record_query_validated(&self) {
        self.queries_validated.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_queries_validated").increment(1);
    }

    /// Record a sent DNS response with a labeled response code.
    /// Emits `dns_responses_sent` and `dns_response_code_total{code}`.
    pub fn record_response_sent(&self, response_code: &str) {
        self.responses_sent.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_responses_sent").increment(1);
        metrics::counter!("dns_response_code_total", "code" => response_code.to_string())
            .increment(1);
    }

    /// Record a cache hit. Emits `dns_cache_hits_total`.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_hits_total").increment(1);
    }

    /// Record a cache miss. Emits `dns_cache_misses_total`.
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_misses_total").increment(1);
    }

    /// Record a stale cache hit. Emits `dns_cache_stale_hits_total`.
    pub fn record_cache_stale_hit(&self) {
        self.cache_stale_hits.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_stale_hits_total").increment(1);
    }

    /// Record a negative cache hit. Emits `dns_cache_negative_hits_total`.
    pub fn record_cache_negative_hit(&self) {
        self.cache_negative_hits.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_negative_hits_total").increment(1);
    }

    /// Record a cache invalidation. Emits `dns_cache_invalidations_total`.
    pub fn record_cache_invalidation(&self) {
        self.cache_invalidations.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_invalidations_total").increment(1);
    }

    /// Record a cache poisoning rejection. Emits `dns_cache_poisoned_rejections_total`.
    pub fn record_cache_poisoned_rejection(&self) {
        self.cache_poisoned_rejections
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_poisoned_rejections_total").increment(1);
    }

    /// Record a cache insertion. Emits `dns_cache_insertions_total`.
    pub fn record_cache_insertion(&self) {
        self.cache_insertions.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_insertions_total").increment(1);
    }

    /// Record a cache size rejection. Emits `dns_cache_size_rejections_total`.
    pub fn record_cache_size_rejection(&self) {
        self.cache_size_rejections.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_cache_size_rejections_total").increment(1);
    }

    /// Record a DNSSEC query. Emits `dnssec_queries_total`.
    pub fn record_dnssec_query(&self) {
        self.dnssec_queries.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dnssec_queries_total").increment(1);
    }

    /// Record a DNSSEC signed response. Emits `dnssec_signed_responses_total`.
    pub fn record_dnssec_signed_response(&self) {
        self.dnssec_signed_responses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dnssec_signed_responses_total").increment(1);
    }

    /// Record a rate-limited query. Emits `dns_rate_limited_total`.
    pub fn record_rate_limited(&self) {
        self.rate_limited_queries.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_rate_limited_total").increment(1);
    }

    /// Record an RRL-limited response. Emits `dns_rrl_limited_total`.
    pub fn record_rrl_limited(&self) {
        self.rrl_limited_responses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_rrl_limited_total").increment(1);
    }

    /// Record a malformed query. Emits `dns_malformed_queries_total`.
    pub fn record_malformed_query(&self) {
        self.malformed_queries.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_malformed_queries_total").increment(1);
    }

    /// Record an NXDOMAIN response. Emits `dns_nxdomain_responses_total`.
    pub fn record_nxdomain(&self) {
        self.nxdomain_responses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_nxdomain_responses_total").increment(1);
    }

    /// Record an encode failure. Emits `dns_encode_failures_total`.
    pub fn record_encode_failure(&self) {
        self.encode_failures.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_encode_failures_total").increment(1);
    }

    /// Record a firewall-allowed query. Emits `dns_firewall_queries_allowed_total`.
    pub fn record_firewall_allowed(&self) {
        self.firewall_queries_allowed
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_firewall_queries_allowed_total").increment(1);
    }

    /// Record a firewall-blocked query. Emits `dns_firewall_queries_blocked_total{rule}`.
    pub fn record_firewall_blocked(&self, rule_id: &str) {
        self.firewall_queries_blocked
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_firewall_queries_blocked_total", "rule" => rule_id.to_string())
            .increment(1);
    }

    /// Record a firewall rule match. Emits `dns_firewall_rule_matches_total{rule}`.
    pub fn record_firewall_rule_match(&self, rule_id: &str) {
        metrics::counter!("dns_firewall_rule_matches_total", "rule" => rule_id.to_string())
            .increment(1);
    }

    /// Record a bailiwick violation. Emits `dns_bailiwick_violations_total`.
    pub fn record_bailiwick_violation(&self) {
        self.bailiwick_violations.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_bailiwick_violations_total").increment(1);
    }

    /// Record a recursive resolver query. Emits `dns_recursive_queries_total`.
    pub fn record_recursive_query(&self) {
        self.recursive_queries.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_queries_total").increment(1);
    }

    /// Record a recursive cache hit. Emits `dns_recursive_cache_hits_total`.
    pub fn record_recursive_cache_hit(&self) {
        self.recursive_cache_hits.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_cache_hits_total").increment(1);
    }

    /// Record a recursive cache miss. Emits `dns_recursive_cache_misses_total`.
    pub fn record_recursive_cache_miss(&self) {
        self.recursive_cache_misses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_cache_misses_total").increment(1);
    }

    /// Record a recursive upstream forward. Emits `dns_recursive_upstream_forwards_total`.
    pub fn record_recursive_upstream_forward(&self) {
        self.recursive_upstream_forwards
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_upstream_forwards_total").increment(1);
    }

    /// Record a recursive upstream failure. Emits `dns_recursive_upstream_failures_total`.
    pub fn record_recursive_upstream_failure(&self) {
        self.recursive_upstream_failures
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_upstream_failures_total").increment(1);
    }

    /// Record a circuit breaker opening. Emits `dns_recursive_circuit_breaker_opens_total`.
    pub fn record_recursive_circuit_breaker_open(&self) {
        self.recursive_circuit_breaker_opens
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_circuit_breaker_opens_total").increment(1);
    }

    /// Record a circuit breaker closing. Emits `dns_recursive_circuit_breaker_closes_total`.
    pub fn record_recursive_circuit_breaker_close(&self) {
        self.recursive_circuit_breaker_closes
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_recursive_circuit_breaker_closes_total").increment(1);
    }

    /// Record a query arriving over a specific transport.
    /// Emits `dns_transport_queries_total{transport}`.
    /// Valid transport keys: "udp", "tcp", "dot", "doh", "doq".
    pub fn record_transport_query(&self, transport: &str) {
        let mut map = self.transport_queries.write();
        let counter = map
            .entry(transport.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_transport_queries_total", "transport" => transport.to_string())
            .increment(1);
    }

    /// Record a transport-layer error.
    /// Emits `dns_transport_errors_total{transport}`.
    pub fn record_transport_error(&self, transport: &str) {
        let mut map = self.transport_errors.write();
        let counter = map
            .entry(transport.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_transport_errors_total", "transport" => transport.to_string())
            .increment(1);
    }

    /// Record a DNS operation by type.
    /// Emits `dns_operation_counts_total{operation}`.
    /// Valid operation keys: "query", "update", "notify", "axfr", "ixfr".
    pub fn record_operation(&self, operation: &str) {
        let mut map = self.operation_counts.write();
        let counter = map
            .entry(operation.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_operation_counts_total", "operation" => operation.to_string())
            .increment(1);
    }

    /// Record a zone successfully loaded. Emits `dns_zones_loaded_total`.
    pub fn record_zone_loaded(&self) {
        self.zones_loaded.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_zones_loaded_total").increment(1);
    }

    /// Record a zone reload success. Emits `dns_zone_reload_successes_total`.
    pub fn record_zone_reload_success(&self) {
        self.zone_reload_successes.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_zone_reload_successes_total").increment(1);
    }

    /// Record a zone reload failure. Emits `dns_zone_reload_failures_total`.
    pub fn record_zone_reload_failure(&self) {
        self.zone_reload_failures.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_zone_reload_failures_total").increment(1);
    }

    /// Record a DNSSEC key rotation. Emits `dns_dnssec_key_rotations_total`.
    pub fn record_dnssec_key_rotation(&self) {
        self.dnssec_key_rotations.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_dnssec_key_rotations_total").increment(1);
    }

    /// Record a DNSSEC signing failure. Emits `dns_dnssec_signing_failures_total`.
    pub fn record_dnssec_signing_failure(&self) {
        self.dnssec_signing_failures.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_dnssec_signing_failures_total").increment(1);
    }

    /// Record an accepted dynamic UPDATE. Emits `dns_update_accepted_total`.
    pub fn record_update_accepted(&self) {
        self.update_accepted.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_update_accepted_total").increment(1);
    }

    /// Record a rejected dynamic UPDATE. Emits `dns_update_rejected_total`.
    pub fn record_update_rejected(&self) {
        self.update_rejected.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_update_rejected_total").increment(1);
    }

    /// Record a sent NOTIFY. Emits `dns_notify_sent_total`.
    pub fn record_notify_sent(&self) {
        self.notify_sent.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_notify_sent_total").increment(1);
    }

    /// Record a received NOTIFY. Emits `dns_notify_received_total`.
    pub fn record_notify_received(&self) {
        self.notify_received.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_notify_received_total").increment(1);
    }

    /// Record an accepted AXFR. Emits `dns_axfr_accepted_total`.
    pub fn record_axfr_accepted(&self) {
        self.axfr_accepted.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_axfr_accepted_total").increment(1);
    }

    /// Record a rejected AXFR. Emits `dns_axfr_rejected_total`.
    pub fn record_axfr_rejected(&self) {
        self.axfr_rejected.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_axfr_rejected_total").increment(1);
    }

    /// Record an accepted IXFR. Emits `dns_ixfr_accepted_total`.
    pub fn record_ixfr_accepted(&self) {
        self.ixfr_accepted.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_ixfr_accepted_total").increment(1);
    }

    /// Record a rejected IXFR. Emits `dns_ixfr_rejected_total`.
    pub fn record_ixfr_rejected(&self) {
        self.ixfr_rejected.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_ixfr_rejected_total").increment(1);
    }

    /// Record a TCP connection. Emits `dns_tcp_connections_total` and increments
    /// the `dns_active_tcp_connections` gauge.
    pub fn record_tcp_connection(&self) {
        self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.active_tcp_connections.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_tcp_connections_total").increment(1);
        metrics::gauge!("dns_active_tcp_connections").increment(1.0);
    }

    /// Record a TCP disconnect. Decrements the `dns_active_tcp_connections` gauge.
    pub fn record_tcp_disconnect(&self) {
        let _ =
            self.active_tcp_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        metrics::gauge!("dns_active_tcp_connections").decrement(1.0);
    }

    /// Record a query latency sample (capped at 1000 samples for bounded memory).
    pub fn record_query_latency(&self, latency_ms: u64) {
        let mut latencies = self.query_latencies.write();
        if latencies.len() < 1000 {
            latencies.push(latency_ms);
        }
    }

    /// Build a point-in-time snapshot of all metrics.
    pub fn get_summary(&self) -> DnsMetricsSummary {
        let queries = self.queries_received.load(Ordering::Relaxed);
        let blocked = self.queries_blocked.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);

        let latencies = self.query_latencies.read();
        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<u64>() / latencies.len() as u64
        } else {
            0
        };

        let p95_latency = if !latencies.is_empty() {
            let mut sorted = latencies.clone();
            sorted.sort();
            let idx = (sorted.len() as f64 * 0.95) as usize;
            sorted.get(idx).copied().unwrap_or(0)
        } else {
            0
        };

        let transport_queries = self
            .transport_queries
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let transport_errors = self
            .transport_errors
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let operation_counts = self
            .operation_counts
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        DnsMetricsSummary {
            queries_received: queries,
            queries_blocked: blocked,
            queries_validated: self.queries_validated.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
            cache_hits,
            cache_misses,
            cache_hit_rate: if cache_hits + cache_misses > 0 {
                (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0
            } else {
                0.0
            },
            cache_stale_hits: self.cache_stale_hits.load(Ordering::Relaxed),
            cache_negative_hits: self.cache_negative_hits.load(Ordering::Relaxed),
            cache_invalidations: self.cache_invalidations.load(Ordering::Relaxed),
            cache_poisoned_rejections: self.cache_poisoned_rejections.load(Ordering::Relaxed),
            cache_insertions: self.cache_insertions.load(Ordering::Relaxed),
            cache_size_rejections: self.cache_size_rejections.load(Ordering::Relaxed),
            dnssec_queries: self.dnssec_queries.load(Ordering::Relaxed),
            dnssec_signed_responses: self.dnssec_signed_responses.load(Ordering::Relaxed),
            rate_limited_queries: self.rate_limited_queries.load(Ordering::Relaxed),
            rrl_limited_responses: self.rrl_limited_responses.load(Ordering::Relaxed),
            malformed_queries: self.malformed_queries.load(Ordering::Relaxed),
            nxdomain_responses: self.nxdomain_responses.load(Ordering::Relaxed),
            encode_failures: self.encode_failures.load(Ordering::Relaxed),
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            active_tcp_connections: self.active_tcp_connections.load(Ordering::Relaxed),
            firewall_queries_allowed: self.firewall_queries_allowed.load(Ordering::Relaxed),
            firewall_queries_blocked: self.firewall_queries_blocked.load(Ordering::Relaxed),
            bailiwick_violations: self.bailiwick_violations.load(Ordering::Relaxed),
            recursive_queries: self.recursive_queries.load(Ordering::Relaxed),
            recursive_cache_hits: self.recursive_cache_hits.load(Ordering::Relaxed),
            recursive_cache_misses: self.recursive_cache_misses.load(Ordering::Relaxed),
            recursive_upstream_forwards: self.recursive_upstream_forwards.load(Ordering::Relaxed),
            recursive_upstream_failures: self.recursive_upstream_failures.load(Ordering::Relaxed),
            recursive_circuit_breaker_opens: self
                .recursive_circuit_breaker_opens
                .load(Ordering::Relaxed),
            recursive_circuit_breaker_closes: self
                .recursive_circuit_breaker_closes
                .load(Ordering::Relaxed),
            transport_queries,
            transport_errors,
            operation_counts,
            zones_loaded: self.zones_loaded.load(Ordering::Relaxed),
            zone_reload_successes: self.zone_reload_successes.load(Ordering::Relaxed),
            zone_reload_failures: self.zone_reload_failures.load(Ordering::Relaxed),
            dnssec_key_rotations: self.dnssec_key_rotations.load(Ordering::Relaxed),
            dnssec_signing_failures: self.dnssec_signing_failures.load(Ordering::Relaxed),
            update_accepted: self.update_accepted.load(Ordering::Relaxed),
            update_rejected: self.update_rejected.load(Ordering::Relaxed),
            notify_sent: self.notify_sent.load(Ordering::Relaxed),
            notify_received: self.notify_received.load(Ordering::Relaxed),
            axfr_accepted: self.axfr_accepted.load(Ordering::Relaxed),
            axfr_rejected: self.axfr_rejected.load(Ordering::Relaxed),
            ixfr_accepted: self.ixfr_accepted.load(Ordering::Relaxed),
            ixfr_rejected: self.ixfr_rejected.load(Ordering::Relaxed),
            avg_query_latency_ms: avg_latency,
            p95_query_latency_ms: p95_latency,
            uptime_seconds: self.last_reset.elapsed().as_secs(),
        }
    }

    /// Reset all counters and clear all labeled maps.
    pub fn reset(&mut self) {
        self.queries_received.store(0, Ordering::Relaxed);
        self.queries_blocked.store(0, Ordering::Relaxed);
        self.queries_validated.store(0, Ordering::Relaxed);
        self.responses_sent.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.cache_stale_hits.store(0, Ordering::Relaxed);
        self.cache_negative_hits.store(0, Ordering::Relaxed);
        self.cache_invalidations.store(0, Ordering::Relaxed);
        self.cache_poisoned_rejections.store(0, Ordering::Relaxed);
        self.cache_insertions.store(0, Ordering::Relaxed);
        self.cache_size_rejections.store(0, Ordering::Relaxed);
        self.dnssec_queries.store(0, Ordering::Relaxed);
        self.dnssec_signed_responses.store(0, Ordering::Relaxed);
        self.rate_limited_queries.store(0, Ordering::Relaxed);
        self.rrl_limited_responses.store(0, Ordering::Relaxed);
        self.malformed_queries.store(0, Ordering::Relaxed);
        self.nxdomain_responses.store(0, Ordering::Relaxed);
        self.encode_failures.store(0, Ordering::Relaxed);
        self.tcp_connections.store(0, Ordering::Relaxed);
        self.active_tcp_connections.store(0, Ordering::Relaxed);
        self.firewall_queries_allowed.store(0, Ordering::Relaxed);
        self.firewall_queries_blocked.store(0, Ordering::Relaxed);
        self.bailiwick_violations.store(0, Ordering::Relaxed);
        self.recursive_queries.store(0, Ordering::Relaxed);
        self.recursive_cache_hits.store(0, Ordering::Relaxed);
        self.recursive_cache_misses.store(0, Ordering::Relaxed);
        self.recursive_upstream_forwards.store(0, Ordering::Relaxed);
        self.recursive_upstream_failures.store(0, Ordering::Relaxed);
        self.recursive_circuit_breaker_opens
            .store(0, Ordering::Relaxed);
        self.recursive_circuit_breaker_closes
            .store(0, Ordering::Relaxed);
        self.zones_loaded.store(0, Ordering::Relaxed);
        self.zone_reload_successes.store(0, Ordering::Relaxed);
        self.zone_reload_failures.store(0, Ordering::Relaxed);
        self.dnssec_key_rotations.store(0, Ordering::Relaxed);
        self.dnssec_signing_failures.store(0, Ordering::Relaxed);
        self.update_accepted.store(0, Ordering::Relaxed);
        self.update_rejected.store(0, Ordering::Relaxed);
        self.notify_sent.store(0, Ordering::Relaxed);
        self.notify_received.store(0, Ordering::Relaxed);
        self.axfr_accepted.store(0, Ordering::Relaxed);
        self.axfr_rejected.store(0, Ordering::Relaxed);
        self.ixfr_accepted.store(0, Ordering::Relaxed);
        self.ixfr_rejected.store(0, Ordering::Relaxed);

        self.transport_queries.write().clear();
        self.transport_errors.write().clear();
        self.operation_counts.write().clear();
        self.query_latencies.write().clear();

        self.last_reset = Instant::now();

        tracing::info!("DNS metrics reset");
    }

    /// Export all counters as Prometheus text exposition format.
    pub fn export_to_prometheus(&self) -> String {
        let summary = self.get_summary();
        let mut output = String::new();

        output.push_str("# HELP dns_queries_received_total Total DNS queries received\n");
        output.push_str("# TYPE dns_queries_received_total counter\n");
        output.push_str(&format!(
            "dns_queries_received_total {}\n\n",
            summary.queries_received
        ));

        output.push_str("# HELP dns_queries_blocked_total Total DNS queries blocked\n");
        output.push_str("# TYPE dns_queries_blocked_total counter\n");
        output.push_str(&format!(
            "dns_queries_blocked_total {}\n\n",
            summary.queries_blocked
        ));

        output.push_str("# HELP dns_queries_validated_total Total DNS queries validated\n");
        output.push_str("# TYPE dns_queries_validated_total counter\n");
        output.push_str(&format!(
            "dns_queries_validated_total {}\n\n",
            summary.queries_validated
        ));

        output.push_str("# HELP dns_responses_sent_total Total DNS responses sent\n");
        output.push_str("# TYPE dns_responses_sent_total counter\n");
        output.push_str(&format!(
            "dns_responses_sent_total {}\n\n",
            summary.responses_sent
        ));

        output.push_str("# HELP dns_cache_hits_total Total DNS cache hits\n");
        output.push_str("# TYPE dns_cache_hits_total counter\n");
        output.push_str(&format!("dns_cache_hits_total {}\n\n", summary.cache_hits));

        output.push_str("# HELP dns_cache_misses_total Total DNS cache misses\n");
        output.push_str("# TYPE dns_cache_misses_total counter\n");
        output.push_str(&format!(
            "dns_cache_misses_total {}\n\n",
            summary.cache_misses
        ));

        output.push_str("# HELP dns_cache_hit_rate Cache hit rate percentage\n");
        output.push_str("# TYPE dns_cache_hit_rate gauge\n");
        output.push_str(&format!(
            "dns_cache_hit_rate {:.2}\n\n",
            summary.cache_hit_rate
        ));

        output.push_str("# HELP dns_cache_stale_hits_total Total DNS cache stale hits\n");
        output.push_str("# TYPE dns_cache_stale_hits_total counter\n");
        output.push_str(&format!(
            "dns_cache_stale_hits_total {}\n\n",
            summary.cache_stale_hits
        ));

        output.push_str("# HELP dns_cache_negative_hits_total Total DNS negative cache hits\n");
        output.push_str("# TYPE dns_cache_negative_hits_total counter\n");
        output.push_str(&format!(
            "dns_cache_negative_hits_total {}\n\n",
            summary.cache_negative_hits
        ));

        output.push_str("# HELP dns_cache_invalidations_total Total DNS cache invalidations\n");
        output.push_str("# TYPE dns_cache_invalidations_total counter\n");
        output.push_str(&format!(
            "dns_cache_invalidations_total {}\n\n",
            summary.cache_invalidations
        ));

        output.push_str(
            "# HELP dns_cache_poisoned_rejections_total Total cache poisoning rejections\n",
        );
        output.push_str("# TYPE dns_cache_poisoned_rejections_total counter\n");
        output.push_str(&format!(
            "dns_cache_poisoned_rejections_total {}\n\n",
            summary.cache_poisoned_rejections
        ));

        output.push_str("# HELP dns_cache_insertions_total Total DNS cache insertions\n");
        output.push_str("# TYPE dns_cache_insertions_total counter\n");
        output.push_str(&format!(
            "dns_cache_insertions_total {}\n\n",
            summary.cache_insertions
        ));

        output.push_str("# HELP dns_cache_size_rejections_total Total cache size rejections\n");
        output.push_str("# TYPE dns_cache_size_rejections_total counter\n");
        output.push_str(&format!(
            "dns_cache_size_rejections_total {}\n\n",
            summary.cache_size_rejections
        ));

        output.push_str("# HELP dns_rate_limited_total Total rate-limited queries\n");
        output.push_str("# TYPE dns_rate_limited_total counter\n");
        output.push_str(&format!(
            "dns_rate_limited_total {}\n\n",
            summary.rate_limited_queries
        ));

        output.push_str("# HELP dns_rrl_limited_total Total RRL-limited responses\n");
        output.push_str("# TYPE dns_rrl_limited_total counter\n");
        output.push_str(&format!(
            "dns_rrl_limited_total {}\n\n",
            summary.rrl_limited_responses
        ));

        output.push_str("# HELP dns_malformed_queries_total Total malformed queries\n");
        output.push_str("# TYPE dns_malformed_queries_total counter\n");
        output.push_str(&format!(
            "dns_malformed_queries_total {}\n\n",
            summary.malformed_queries
        ));

        output.push_str("# HELP dns_encode_failures_total Total record encode failures\n");
        output.push_str("# TYPE dns_encode_failures_total counter\n");
        output.push_str(&format!(
            "dns_encode_failures_total {}\n\n",
            summary.encode_failures
        ));

        output
            .push_str("# HELP dns_firewall_queries_allowed_total Total firewall-allowed queries\n");
        output.push_str("# TYPE dns_firewall_queries_allowed_total counter\n");
        output.push_str(&format!(
            "dns_firewall_queries_allowed_total {}\n\n",
            summary.firewall_queries_allowed
        ));

        output
            .push_str("# HELP dns_firewall_queries_blocked_total Total firewall-blocked queries\n");
        output.push_str("# TYPE dns_firewall_queries_blocked_total counter\n");
        output.push_str(&format!(
            "dns_firewall_queries_blocked_total {}\n\n",
            summary.firewall_queries_blocked
        ));

        output.push_str("# HELP dns_bailiwick_violations_total Total bailiwick violations\n");
        output.push_str("# TYPE dns_bailiwick_violations_total counter\n");
        output.push_str(&format!(
            "dns_bailiwick_violations_total {}\n\n",
            summary.bailiwick_violations
        ));

        output.push_str("# HELP dns_active_tcp_connections Current active TCP connections\n");
        output.push_str("# TYPE dns_active_tcp_connections gauge\n");
        output.push_str(&format!(
            "dns_active_tcp_connections {}\n\n",
            summary.active_tcp_connections
        ));

        output.push_str("# HELP dns_recursive_queries_total Total recursive resolver queries\n");
        output.push_str("# TYPE dns_recursive_queries_total counter\n");
        output.push_str(&format!(
            "dns_recursive_queries_total {}\n\n",
            summary.recursive_queries
        ));

        output.push_str("# HELP dns_recursive_cache_hits_total Total recursive cache hits\n");
        output.push_str("# TYPE dns_recursive_cache_hits_total counter\n");
        output.push_str(&format!(
            "dns_recursive_cache_hits_total {}\n\n",
            summary.recursive_cache_hits
        ));

        output.push_str("# HELP dns_recursive_cache_misses_total Total recursive cache misses\n");
        output.push_str("# TYPE dns_recursive_cache_misses_total counter\n");
        output.push_str(&format!(
            "dns_recursive_cache_misses_total {}\n\n",
            summary.recursive_cache_misses
        ));

        output.push_str(
            "# HELP dns_recursive_upstream_forwards_total Total recursive upstream forwards\n",
        );
        output.push_str("# TYPE dns_recursive_upstream_forwards_total counter\n");
        output.push_str(&format!(
            "dns_recursive_upstream_forwards_total {}\n\n",
            summary.recursive_upstream_forwards
        ));

        output.push_str(
            "# HELP dns_recursive_upstream_failures_total Total recursive upstream failures\n",
        );
        output.push_str("# TYPE dns_recursive_upstream_failures_total counter\n");
        output.push_str(&format!(
            "dns_recursive_upstream_failures_total {}\n\n",
            summary.recursive_upstream_failures
        ));

        output.push_str(
            "# HELP dns_recursive_circuit_breaker_opens_total Circuit breaker open events\n",
        );
        output.push_str("# TYPE dns_recursive_circuit_breaker_opens_total counter\n");
        output.push_str(&format!(
            "dns_recursive_circuit_breaker_opens_total {}\n\n",
            summary.recursive_circuit_breaker_opens
        ));

        output.push_str(
            "# HELP dns_recursive_circuit_breaker_closes_total Circuit breaker close events\n",
        );
        output.push_str("# TYPE dns_recursive_circuit_breaker_closes_total counter\n");
        output.push_str(&format!(
            "dns_recursive_circuit_breaker_closes_total {}\n\n",
            summary.recursive_circuit_breaker_closes
        ));

        for (transport, count) in &summary.transport_queries {
            output.push_str(&format!(
                "# HELP dns_transport_queries_total{{transport=\"{transport}\"}} Queries by transport\n"
            ));
            output.push_str(&format!("# TYPE dns_transport_queries_total counter\n"));
            output.push_str(&format!(
                "dns_transport_queries_total{{transport=\"{transport}\"}} {count}\n\n"
            ));
        }

        for (transport, count) in &summary.transport_errors {
            output.push_str(&format!(
                "# HELP dns_transport_errors_total{{transport=\"{transport}\"}} Transport errors\n"
            ));
            output.push_str(&format!("# TYPE dns_transport_errors_total counter\n"));
            output.push_str(&format!(
                "dns_transport_errors_total{{transport=\"{transport}\"}} {count}\n\n"
            ));
        }

        for (operation, count) in &summary.operation_counts {
            output.push_str(&format!(
                "# HELP dns_operation_counts_total{{operation=\"{operation}\"}} Operations by type\n"
            ));
            output.push_str(&format!("# TYPE dns_operation_counts_total counter\n"));
            output.push_str(&format!(
                "dns_operation_counts_total{{operation=\"{operation}\"}} {count}\n\n"
            ));
        }

        output.push_str("# HELP dns_zones_loaded_total Total zones loaded\n");
        output.push_str("# TYPE dns_zones_loaded_total counter\n");
        output.push_str(&format!(
            "dns_zones_loaded_total {}\n\n",
            summary.zones_loaded
        ));

        output.push_str("# HELP dns_zone_reload_successes_total Total successful zone reloads\n");
        output.push_str("# TYPE dns_zone_reload_successes_total counter\n");
        output.push_str(&format!(
            "dns_zone_reload_successes_total {}\n\n",
            summary.zone_reload_successes
        ));

        output.push_str("# HELP dns_zone_reload_failures_total Total failed zone reloads\n");
        output.push_str("# TYPE dns_zone_reload_failures_total counter\n");
        output.push_str(&format!(
            "dns_zone_reload_failures_total {}\n\n",
            summary.zone_reload_failures
        ));

        output.push_str("# HELP dns_dnssec_key_rotations_total Total DNSSEC key rotations\n");
        output.push_str("# TYPE dns_dnssec_key_rotations_total counter\n");
        output.push_str(&format!(
            "dns_dnssec_key_rotations_total {}\n\n",
            summary.dnssec_key_rotations
        ));

        output.push_str("# HELP dns_dnssec_signing_failures_total Total DNSSEC signing failures\n");
        output.push_str("# TYPE dns_dnssec_signing_failures_total counter\n");
        output.push_str(&format!(
            "dns_dnssec_signing_failures_total {}\n\n",
            summary.dnssec_signing_failures
        ));

        output.push_str("# HELP dns_update_accepted_total Total accepted dynamic UPDATEs\n");
        output.push_str("# TYPE dns_update_accepted_total counter\n");
        output.push_str(&format!(
            "dns_update_accepted_total {}\n\n",
            summary.update_accepted
        ));

        output.push_str("# HELP dns_update_rejected_total Total rejected dynamic UPDATEs\n");
        output.push_str("# TYPE dns_update_rejected_total counter\n");
        output.push_str(&format!(
            "dns_update_rejected_total {}\n\n",
            summary.update_rejected
        ));

        output.push_str("# HELP dns_notify_sent_total Total sent NOTIFYs\n");
        output.push_str("# TYPE dns_notify_sent_total counter\n");
        output.push_str(&format!(
            "dns_notify_sent_total {}\n\n",
            summary.notify_sent
        ));

        output.push_str("# HELP dns_notify_received_total Total received NOTIFYs\n");
        output.push_str("# TYPE dns_notify_received_total counter\n");
        output.push_str(&format!(
            "dns_notify_received_total {}\n\n",
            summary.notify_received
        ));

        output.push_str("# HELP dns_axfr_accepted_total Total accepted AXFR requests\n");
        output.push_str("# TYPE dns_axfr_accepted_total counter\n");
        output.push_str(&format!(
            "dns_axfr_accepted_total {}\n\n",
            summary.axfr_accepted
        ));

        output.push_str("# HELP dns_axfr_rejected_total Total rejected AXFR requests\n");
        output.push_str("# TYPE dns_axfr_rejected_total counter\n");
        output.push_str(&format!(
            "dns_axfr_rejected_total {}\n\n",
            summary.axfr_rejected
        ));

        output.push_str("# HELP dns_ixfr_accepted_total Total accepted IXFR requests\n");
        output.push_str("# TYPE dns_ixfr_accepted_total counter\n");
        output.push_str(&format!(
            "dns_ixfr_accepted_total {}\n\n",
            summary.ixfr_accepted
        ));

        output.push_str("# HELP dns_ixfr_rejected_total Total rejected IXFR requests\n");
        output.push_str("# TYPE dns_ixfr_rejected_total counter\n");
        output.push_str(&format!(
            "dns_ixfr_rejected_total {}\n\n",
            summary.ixfr_rejected
        ));

        output.push_str("# HELP dns_avg_query_latency_ms Average query latency in milliseconds\n");
        output.push_str("# TYPE dns_avg_query_latency_ms gauge\n");
        output.push_str(&format!(
            "dns_avg_query_latency_ms {}\n\n",
            summary.avg_query_latency_ms
        ));

        output
    }
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DnsMetricsSummary {
    pub queries_received: u64,
    pub queries_blocked: u64,
    pub queries_validated: u64,
    pub responses_sent: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub cache_stale_hits: u64,
    pub cache_negative_hits: u64,
    pub cache_invalidations: u64,
    pub cache_poisoned_rejections: u64,
    pub cache_insertions: u64,
    pub cache_size_rejections: u64,
    pub dnssec_queries: u64,
    pub dnssec_signed_responses: u64,
    pub rate_limited_queries: u64,
    pub rrl_limited_responses: u64,
    pub malformed_queries: u64,
    pub nxdomain_responses: u64,
    pub encode_failures: u64,
    pub tcp_connections: usize,
    pub active_tcp_connections: usize,
    pub firewall_queries_allowed: u64,
    pub firewall_queries_blocked: u64,
    pub bailiwick_violations: u64,
    pub recursive_queries: u64,
    pub recursive_cache_hits: u64,
    pub recursive_cache_misses: u64,
    pub recursive_upstream_forwards: u64,
    pub recursive_upstream_failures: u64,
    pub recursive_circuit_breaker_opens: u64,
    pub recursive_circuit_breaker_closes: u64,
    pub transport_queries: HashMap<String, u64>,
    pub transport_errors: HashMap<String, u64>,
    pub operation_counts: HashMap<String, u64>,
    pub zones_loaded: u64,
    pub zone_reload_successes: u64,
    pub zone_reload_failures: u64,
    pub dnssec_key_rotations: u64,
    pub dnssec_signing_failures: u64,
    pub update_accepted: u64,
    pub update_rejected: u64,
    pub notify_sent: u64,
    pub notify_received: u64,
    pub axfr_accepted: u64,
    pub axfr_rejected: u64,
    pub ixfr_accepted: u64,
    pub ixfr_rejected: u64,
    pub avg_query_latency_ms: u64,
    pub p95_query_latency_ms: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct DnsSecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: DnsSecurityEventType,
    pub source_ip: Option<String>,
    pub domain: Option<String>,
    pub details: String,
    pub severity: DnsSecurityEventSeverity,
}

#[derive(Debug, Clone)]
pub enum DnsSecurityEventType {
    QueryBlocked,
    RateLimitExceeded,
    RrlExceeded,
    MalformedQuery,
    CachePoisoningAttempt,
    DnssecValidationFailed,
    ZoneTransferAttempt,
    UnauthorizedAccess,
    FirewallRuleMatch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsSecurityEventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct DnsSecurityLogger {
    events: RwLock<Vec<DnsSecurityEvent>>,
    max_events: usize,
}

impl DnsSecurityLogger {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: RwLock::new(Vec::with_capacity(max_events)),
            max_events,
        }
    }

    pub fn log_event(&self, event: DnsSecurityEvent) {
        let mut events = self.events.write();

        if events.len() >= self.max_events {
            events.remove(0);
        }

        events.push(event.clone());

        match event.severity {
            DnsSecurityEventSeverity::Critical => {
                tracing::error!("DNS security event: {:?}", event);
            }
            DnsSecurityEventSeverity::High => {
                tracing::warn!("DNS security event: {:?}", event);
            }
            DnsSecurityEventSeverity::Medium => {
                tracing::debug!("DNS security event: {:?}", event);
            }
            DnsSecurityEventSeverity::Low => {
                tracing::trace!("DNS security event: {:?}", event);
            }
        }
    }

    pub fn get_recent_events(&self, count: usize) -> Vec<DnsSecurityEvent> {
        let events = self.events.read();
        events.iter().rev().take(count).cloned().collect()
    }

    pub fn get_events_by_severity(
        &self,
        severity: DnsSecurityEventSeverity,
    ) -> Vec<DnsSecurityEvent> {
        let events = self.events.read();
        events
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        let mut events = self.events.write();
        events.clear();
    }
}

impl Default for DnsSecurityLogger {
    fn default() -> Self {
        Self::new(10000)
    }
}
