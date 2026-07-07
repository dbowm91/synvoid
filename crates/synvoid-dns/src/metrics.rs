use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

/// DNS metrics collector with atomic counters and labeled `metrics::counter!` emissions.
pub struct DnsMetrics {
    queries_received: AtomicU64,
    responses_sent: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_stale_hits: AtomicU64,
    cache_negative_hits: AtomicU64,
    cache_invalidations: AtomicU64,
    cache_poisoned_rejections: AtomicU64,
    cache_insertions: AtomicU64,
    cache_size_rejections: AtomicU64,
    rate_limited_queries: AtomicU64,
    firewall_queries_blocked: AtomicU64,
    bailiwick_violations: AtomicU64,

    recursive_queries: AtomicU64,
    recursive_cache_hits: AtomicU64,
    recursive_cache_misses: AtomicU64,
    recursive_upstream_forwards: AtomicU64,
    recursive_upstream_failures: AtomicU64,

    last_reset: Instant,
}

impl DnsMetrics {
    pub fn new() -> Self {
        Self {
            queries_received: AtomicU64::new(0),
            responses_sent: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_stale_hits: AtomicU64::new(0),
            cache_negative_hits: AtomicU64::new(0),
            cache_invalidations: AtomicU64::new(0),
            cache_poisoned_rejections: AtomicU64::new(0),
            cache_insertions: AtomicU64::new(0),
            cache_size_rejections: AtomicU64::new(0),
            rate_limited_queries: AtomicU64::new(0),
            firewall_queries_blocked: AtomicU64::new(0),
            bailiwick_violations: AtomicU64::new(0),
            recursive_queries: AtomicU64::new(0),
            recursive_cache_hits: AtomicU64::new(0),
            recursive_cache_misses: AtomicU64::new(0),
            recursive_upstream_forwards: AtomicU64::new(0),
            recursive_upstream_failures: AtomicU64::new(0),
            last_reset: Instant::now(),
        }
    }

    /// Record an incoming DNS query. Emits `dns_queries_received`.
    pub fn record_query_received(&self) {
        self.queries_received.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_queries_received").increment(1);
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

    /// Record a rate-limited query. Emits `dns_rate_limited_total`.
    pub fn record_rate_limited(&self) {
        self.rate_limited_queries.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_rate_limited_total").increment(1);
    }

    /// Record a firewall-blocked query. Emits `dns_firewall_queries_blocked_total{rule}`.
    pub fn record_firewall_blocked(&self, rule_id: &str) {
        self.firewall_queries_blocked
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("dns_firewall_queries_blocked_total", "rule" => rule_id.to_string())
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

    /// Build a point-in-time snapshot of all metrics.
    pub fn get_summary(&self) -> DnsMetricsSummary {
        let queries = self.queries_received.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);

        DnsMetricsSummary {
            queries_received: queries,
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
            rate_limited_queries: self.rate_limited_queries.load(Ordering::Relaxed),
            firewall_queries_blocked: self.firewall_queries_blocked.load(Ordering::Relaxed),
            bailiwick_violations: self.bailiwick_violations.load(Ordering::Relaxed),
            recursive_queries: self.recursive_queries.load(Ordering::Relaxed),
            recursive_cache_hits: self.recursive_cache_hits.load(Ordering::Relaxed),
            recursive_cache_misses: self.recursive_cache_misses.load(Ordering::Relaxed),
            recursive_upstream_forwards: self.recursive_upstream_forwards.load(Ordering::Relaxed),
            recursive_upstream_failures: self.recursive_upstream_failures.load(Ordering::Relaxed),
            uptime_seconds: self.last_reset.elapsed().as_secs(),
        }
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        self.queries_received.store(0, Ordering::Relaxed);
        self.responses_sent.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.cache_stale_hits.store(0, Ordering::Relaxed);
        self.cache_negative_hits.store(0, Ordering::Relaxed);
        self.cache_invalidations.store(0, Ordering::Relaxed);
        self.cache_poisoned_rejections.store(0, Ordering::Relaxed);
        self.cache_insertions.store(0, Ordering::Relaxed);
        self.cache_size_rejections.store(0, Ordering::Relaxed);
        self.rate_limited_queries.store(0, Ordering::Relaxed);
        self.firewall_queries_blocked.store(0, Ordering::Relaxed);
        self.bailiwick_violations.store(0, Ordering::Relaxed);
        self.recursive_queries.store(0, Ordering::Relaxed);
        self.recursive_cache_hits.store(0, Ordering::Relaxed);
        self.recursive_cache_misses.store(0, Ordering::Relaxed);
        self.recursive_upstream_forwards.store(0, Ordering::Relaxed);
        self.recursive_upstream_failures.store(0, Ordering::Relaxed);

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
    pub rate_limited_queries: u64,
    pub firewall_queries_blocked: u64,
    pub bailiwick_violations: u64,
    pub recursive_queries: u64,
    pub recursive_cache_hits: u64,
    pub recursive_cache_misses: u64,
    pub recursive_upstream_forwards: u64,
    pub recursive_upstream_failures: u64,
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
