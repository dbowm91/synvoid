use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

pub struct DnsMetrics {
    queries_received: AtomicU64,
    queries_blocked: AtomicU64,
    queries_validated: AtomicU64,
    responses_sent: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    dnssec_queries: AtomicU64,
    dnssec_signed_responses: AtomicU64,
    rate_limited_queries: AtomicU64,
    rrl_limited_responses: AtomicU64,
    malformed_queries: AtomicU64,
    nxdomain_responses: AtomicU64,
    encode_failures: AtomicU64,
    tcp_connections: AtomicUsize,
    active_tcp_connections: AtomicUsize,
    query_types: RwLock<HashMap<String, AtomicU64>>,
    top_queried_domains: RwLock<HashMap<String, AtomicU64>>,
    top_blocked_domains: RwLock<HashMap<String, AtomicU64>>,
    response_codes: RwLock<HashMap<String, AtomicU64>>,
    query_latencies: RwLock<Vec<u64>>,
    firewall_queries_allowed: AtomicU64,
    firewall_queries_blocked: AtomicU64,
    firewall_rule_matches: RwLock<HashMap<String, AtomicU64>>,
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
            dnssec_queries: AtomicU64::new(0),
            dnssec_signed_responses: AtomicU64::new(0),
            rate_limited_queries: AtomicU64::new(0),
            rrl_limited_responses: AtomicU64::new(0),
            malformed_queries: AtomicU64::new(0),
            nxdomain_responses: AtomicU64::new(0),
            encode_failures: AtomicU64::new(0),
            tcp_connections: AtomicUsize::new(0),
            active_tcp_connections: AtomicUsize::new(0),
            query_types: RwLock::new(HashMap::new()),
            top_queried_domains: RwLock::new(HashMap::new()),
            top_blocked_domains: RwLock::new(HashMap::new()),
            response_codes: RwLock::new(HashMap::new()),
            query_latencies: RwLock::new(Vec::new()),
            firewall_queries_allowed: AtomicU64::new(0),
            firewall_queries_blocked: AtomicU64::new(0),
            firewall_rule_matches: RwLock::new(HashMap::new()),
            last_reset: Instant::now(),
        }
    }

    pub fn record_query_received(&self) {
        self.queries_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_query_blocked(&self, domain: &str) {
        self.queries_blocked.fetch_add(1, Ordering::Relaxed);
        let mut blocked = self.top_blocked_domains.write();
        let counter = blocked
            .entry(domain.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_query_validated(&self) {
        self.queries_validated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_response_sent(&self, response_code: &str) {
        self.responses_sent.fetch_add(1, Ordering::Relaxed);
        let mut codes = self.response_codes.write();
        let counter = codes
            .entry(response_code.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dnssec_query(&self) {
        self.dnssec_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dnssec_signed_response(&self) {
        self.dnssec_signed_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.rate_limited_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rrl_limited(&self) {
        self.rrl_limited_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_malformed_query(&self) {
        self.malformed_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_nxdomain(&self) {
        self.nxdomain_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_encode_failure(&self) {
        self.encode_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_firewall_allowed(&self) {
        self.firewall_queries_allowed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_firewall_blocked(&self, rule_id: &str) {
        self.firewall_queries_blocked
            .fetch_add(1, Ordering::Relaxed);
        let mut rules = self.firewall_rule_matches.write();
        let counter = rules
            .entry(rule_id.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_firewall_rule_match(&self, rule_id: &str) {
        let mut rules = self.firewall_rule_matches.write();
        let counter = rules
            .entry(rule_id.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_connection(&self) {
        self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.active_tcp_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_disconnect(&self) {
        let _ =
            self.active_tcp_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    pub fn record_query_type(&self, qtype: &str) {
        let mut types = self.query_types.write();
        let counter = types
            .entry(qtype.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_queried_domain(&self, domain: &str) {
        let mut domains = self.top_queried_domains.write();
        let counter = domains
            .entry(domain.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_query_latency(&self, latency_ms: u64) {
        let mut latencies = self.query_latencies.write();
        if latencies.len() < 1000 {
            latencies.push(latency_ms);
        }
    }

    pub fn get_summary(&self) -> DnsMetricsSummary {
        let queries = self.queries_received.load(Ordering::Relaxed);
        let blocked = self.queries_blocked.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);

        let query_types = self
            .query_types
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let top_domains = self
            .top_queried_domains
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let top_blocked = self
            .top_blocked_domains
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let response_codes = self
            .response_codes
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

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
            firewall_rule_matches: self
                .firewall_rule_matches
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
                .collect(),
            query_types,
            top_queried_domains: top_domains,
            top_blocked_domains: top_blocked,
            response_codes,
            avg_query_latency_ms: avg_latency,
            p95_query_latency_ms: p95_latency,
            uptime_seconds: self.last_reset.elapsed().as_secs(),
        }
    }

    pub fn reset(&mut self) {
        self.queries_received.store(0, Ordering::Relaxed);
        self.queries_blocked.store(0, Ordering::Relaxed);
        self.queries_validated.store(0, Ordering::Relaxed);
        self.responses_sent.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
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

        self.query_types.write().clear();
        self.top_queried_domains.write().clear();
        self.top_blocked_domains.write().clear();
        self.response_codes.write().clear();
        self.query_latencies.write().clear();

        self.last_reset = Instant::now();

        tracing::info!("DNS metrics reset");
    }

    pub fn export_to_prometheus(&self) -> String {
        let summary = self.get_summary();
        let mut output = String::new();

        output.push_str("# HELP dns_queries_received Total DNS queries received\n");
        output.push_str("# TYPE dns_queries_received counter\n");
        output.push_str(&format!(
            "dns_queries_received {}\n\n",
            summary.queries_received
        ));

        output.push_str("# HELP dns_queries_blocked Total DNS queries blocked\n");
        output.push_str("# TYPE dns_queries_blocked counter\n");
        output.push_str(&format!(
            "dns_queries_blocked {}\n\n",
            summary.queries_blocked
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

        output.push_str("# HELP dns_firewall_queries_allowed Total firewall-allowed queries\n");
        output.push_str("# TYPE dns_firewall_queries_allowed counter\n");
        output.push_str(&format!(
            "dns_firewall_queries_allowed {}\n\n",
            summary.firewall_queries_allowed
        ));

        output.push_str("# HELP dns_firewall_queries_blocked Total firewall-blocked queries\n");
        output.push_str("# TYPE dns_firewall_queries_blocked counter\n");
        output.push_str(&format!(
            "dns_firewall_queries_blocked {}\n\n",
            summary.firewall_queries_blocked
        ));

        output.push_str("# HELP dns_active_tcp_connections Current active TCP connections\n");
        output.push_str("# TYPE dns_active_tcp_connections gauge\n");
        output.push_str(&format!(
            "dns_active_tcp_connections {}\n\n",
            summary.active_tcp_connections
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
    pub firewall_rule_matches: HashMap<String, u64>,
    pub query_types: HashMap<String, u64>,
    pub top_queried_domains: HashMap<String, u64>,
    pub top_blocked_domains: HashMap<String, u64>,
    pub response_codes: HashMap<String, u64>,
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
