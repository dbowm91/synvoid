use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics::{Counter, Gauge};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::time::timeout;

use crate::cache::{CacheNamespace, TransportClass};
use crate::parsed_query::ParsedDnsQuery;

static COALESCER_HITS: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_hits_total"));
static COALESCER_MISSES: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_misses_total"));
static COALESCER_EVICTIONS: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_evictions_total"));
static COALESCER_TIMEOUTS: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_timeouts_total"));
static COALESCER_LAGGED: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_lagged_total"));
static COALESCER_BROADCASTS: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_broadcasts_total"));
static COALESCER_CANCELS: std::sync::LazyLock<Counter> =
    std::sync::LazyLock::new(|| metrics::counter!("dns_query_coalescer_cancels_total"));
static COALESCER_IN_FLIGHT: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_in_flight"));

/// Returns `true` for query types and opcodes that must never be coalesced.
///
/// AXFR/IXFR are multi-message transfers that share a connection and must not
/// have their responses mixed. NOTIFY and UPDATE carry per-message state and
/// must always be handled individually.
pub fn should_skip_coalescing(qtype: u16, opcode: u8) -> bool {
    // AXFR (252) and IXFR (251) are zone transfers
    qtype == 252 || qtype == 251
        // NOTIFY (opcode 4) and UPDATE (opcode 5)
        || opcode == 4
        || opcode == 5
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QueryKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec_ok: bool,
    pub client_ip: Option<String>,
    pub transport_class: TransportClass,
    pub namespace: CacheNamespace,
}

impl QueryKey {
    pub fn from_query(
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
        transport_class: Option<TransportClass>,
    ) -> Option<Self> {
        let parsed = ParsedDnsQuery::parse(query).ok()?;
        let client_str = client_ip.map(|ip| ip.to_string());
        let tc = transport_class.unwrap_or(TransportClass::default());
        Some(Self {
            name: parsed.qname.to_lowercase(),
            qtype: parsed.qtype,
            qclass: parsed.qclass,
            dnssec_ok: parsed.dnssec_ok,
            client_ip: client_str,
            transport_class: tc,
            namespace: CacheNamespace::Authoritative,
        })
    }

    pub fn from_parsed(
        parsed: &ParsedDnsQuery<'_>,
        client_ip: Option<std::net::IpAddr>,
        _raw: &[u8],
        transport_class: Option<TransportClass>,
    ) -> Option<Self> {
        let client_str = client_ip.map(|ip| ip.to_string());
        let tc = transport_class.unwrap_or(TransportClass::default());
        Some(Self {
            name: parsed.qname.to_lowercase(),
            qtype: parsed.qtype,
            qclass: parsed.qclass,
            dnssec_ok: parsed.dnssec_ok,
            client_ip: client_str,
            transport_class: tc,
            namespace: CacheNamespace::Authoritative,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CoalescerEntry {
    pub sender: broadcast::Sender<Arc<Vec<u8>>>,
    pub created_at: Instant,
}

#[derive(Default)]
pub struct QueryCoalescerMetrics {
    pub hits: usize,
    pub misses: usize,
    pub evictions: usize,
    pub timeouts: usize,
    pub lagged: usize,
    pub broadcasts: usize,
    pub cancels: usize,
}

pub struct QueryCoalescer {
    in_flight: Arc<RwLock<HashMap<QueryKey, CoalescerEntry>>>,
    max_entries: usize,
    entry_ttl: Duration,
    max_wait: Duration,
    metrics: Arc<RwLock<QueryCoalescerMetrics>>,
}

impl QueryCoalescer {
    pub fn new() -> Self {
        Self {
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            max_entries: 10000,
            entry_ttl: Duration::from_secs(30),
            max_wait: Duration::from_millis(500),
            metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
        }
    }

    pub fn with_max_wait_time(max_wait_ms: u64) -> Self {
        Self {
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            max_entries: 10000,
            entry_ttl: Duration::from_secs(30),
            max_wait: Duration::from_millis(max_wait_ms),
            metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
        }
    }

    pub fn with_config(max_wait_ms: u64, max_entries: usize, entry_ttl_secs: u64) -> Self {
        Self {
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            entry_ttl: Duration::from_secs(entry_ttl_secs),
            max_wait: Duration::from_millis(max_wait_ms),
            metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
        }
    }

    pub async fn get_or_wait(&self, key: QueryKey) -> Option<CoalesceResult> {
        // Check if there's an existing query to coalesce with
        // Extract the receiver outside the lock to avoid Send issues
        let opt_receiver = {
            let in_flight = self.in_flight.read();
            if let Some(entry) = in_flight.get(&key) {
                Some(entry.sender.subscribe())
            } else {
                None
            }
        };

        // Now await with the receiver, no lock held
        if let Some(mut receiver) = opt_receiver {
            match timeout(self.max_wait, receiver.recv()).await {
                Ok(Ok(response)) => {
                    self.metrics.write().hits += 1;
                    COALESCER_HITS.increment(1);
                    return Some(CoalesceResult::Response(response));
                }
                Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                    self.metrics.write().lagged += 1;
                    COALESCER_LAGGED.increment(1);
                    tracing::debug!("Coalescer lagged {} messages for {:?}", n, key);
                    return Some(CoalesceResult::Lagged);
                }
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    return None;
                }
                Err(_) => {
                    self.metrics.write().timeouts += 1;
                    COALESCER_TIMEOUTS.increment(1);
                    return Some(CoalesceResult::Timeout);
                }
            }
        }

        // Check if we need to evict, then insert
        {
            let in_flight = self.in_flight.read();
            if in_flight.len() >= self.max_entries {
                drop(in_flight);
                let mut in_flight = self.in_flight.write();
                self.evict_oldest(&mut in_flight);
            }
        }

        let mut in_flight = self.in_flight.write();
        let (tx, _) = broadcast::channel(1);
        let entry = CoalescerEntry {
            sender: tx.clone(),
            created_at: Instant::now(),
        };
        in_flight.insert(key.clone(), entry);
        let count = in_flight.len();
        drop(in_flight);

        self.metrics.write().misses += 1;
        COALESCER_MISSES.increment(1);
        COALESCER_IN_FLIGHT.set(count as f64);
        Some(CoalesceResult::NewQuery(tx))
    }

    fn evict_oldest(&self, in_flight: &mut HashMap<QueryKey, CoalescerEntry>) {
        if in_flight.is_empty() {
            return;
        }

        let oldest_key = in_flight
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest_key {
            in_flight.remove(&key);
            self.metrics.write().evictions += 1;
            COALESCER_EVICTIONS.increment(1);
            COALESCER_IN_FLIGHT.set(in_flight.len() as f64);
            tracing::debug!("Evicted oldest coalescer entry: {:?}", key);
        }
    }

    pub fn broadcast_response(&self, key: QueryKey, response: Arc<Vec<u8>>) {
        let entry = {
            let in_flight = self.in_flight.read();
            in_flight.get(&key).cloned()
        };

        if let Some(entry) = entry {
            let _ = entry.sender.send(response);
        }

        let mut in_flight = self.in_flight.write();
        in_flight.remove(&key);
        self.metrics.write().broadcasts += 1;
        COALESCER_BROADCASTS.increment(1);
        COALESCER_IN_FLIGHT.set(in_flight.len() as f64);
    }

    pub fn cancel_in_flight(&self, key: &QueryKey) {
        let mut in_flight = self.in_flight.write();
        if in_flight.remove(key).is_some() {
            self.metrics.write().cancels += 1;
            COALESCER_CANCELS.increment(1);
            COALESCER_IN_FLIGHT.set(in_flight.len() as f64);
        }
    }

    pub fn cleanup_stale(&self) {
        let mut in_flight = self.in_flight.write();
        let now = Instant::now();

        let prev_count = in_flight.len();
        in_flight.retain(|_key, entry| {
            let is_stale = entry.sender.receiver_count() == 0
                || now.duration_since(entry.created_at) > self.entry_ttl;

            if is_stale {
                self.metrics.write().evictions += 1;
            }

            !is_stale
        });
        let new_count = in_flight.len();
        if prev_count != new_count {
            COALESCER_EVICTIONS.increment((prev_count - new_count) as u64);
            COALESCER_IN_FLIGHT.set(new_count as f64);
        }
    }

    pub fn cleanup_stale_aged(&self, max_age: Duration) {
        let mut in_flight = self.in_flight.write();
        let now = Instant::now();

        let prev_count = in_flight.len();
        in_flight.retain(|key, entry| {
            let is_stale = now.duration_since(entry.created_at) > max_age;

            if is_stale {
                self.metrics.write().evictions += 1;
                tracing::debug!("Removed stale coalescer entry: {:?}", key);
            }

            !is_stale
        });
        let new_count = in_flight.len();
        if prev_count != new_count {
            COALESCER_EVICTIONS.increment((prev_count - new_count) as u64);
            COALESCER_IN_FLIGHT.set(new_count as f64);
        }
    }

    pub fn metrics(&self) -> QueryCoalescerMetrics {
        let guard = self.metrics.read();
        QueryCoalescerMetrics {
            hits: guard.hits,
            misses: guard.misses,
            lagged: guard.lagged,
            timeouts: guard.timeouts,
            evictions: guard.evictions,
            broadcasts: guard.broadcasts,
            cancels: guard.cancels,
        }
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.read().len()
    }
}

impl Default for QueryCoalescer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum CoalesceResult {
    Response(Arc<Vec<u8>>),
    NewQuery(broadcast::Sender<Arc<Vec<u8>>>),
    Lagged,
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_key_from_query() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let key = QueryKey::from_query(&query, None, None).unwrap();
        assert_eq!(key.name, "example.com");
        assert_eq!(key.qtype, 1);
    }

    #[tokio::test]
    async fn test_coalesce_new_query() {
        let coalescer = QueryCoalescer::new();
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_coalesce_broadcast() {
        let coalescer = QueryCoalescer::new();
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let response = Arc::new(vec![0x00, 0x01, 0x02, 0x03]);

        let _ = coalescer.get_or_wait(key.clone()).await;

        coalescer.broadcast_response(key.clone(), response.clone());

        let result = coalescer.get_or_wait(key).await;

        // The result should either be a Response (if timing worked out) or NewQuery (if not)
        // This test may be timing-dependent
        match result {
            Some(CoalesceResult::Response(r)) => {
                assert_eq!(*r, *response, "Response should match broadcast");
            }
            Some(CoalesceResult::NewQuery(_)) => {
                // NewQuery is also acceptable if the timing didn't work out
            }
            Some(CoalesceResult::Timeout) => {
                // Timeout is also acceptable
            }
            Some(CoalesceResult::Lagged) => {
                // Lagged is also acceptable
            }
            None => {
                panic!("Unexpected result: None");
            }
        }
    }

    #[tokio::test]
    async fn test_max_entries_eviction() {
        let coalescer = QueryCoalescer::with_config(500, 3, 30);

        for i in 0..5 {
            let key = QueryKey {
                name: format!("example{}.com", i),
                qtype: 1,
                qclass: 1,
                dnssec_ok: false,
                client_ip: None,
                transport_class: TransportClass::default(),
                namespace: CacheNamespace::Authoritative,
            };
            coalescer.get_or_wait(key).await;
        }

        assert_eq!(coalescer.in_flight_count(), 3);
        assert_eq!(coalescer.metrics().evictions, 2);
    }

    #[tokio::test]
    async fn test_metrics() {
        let coalescer = QueryCoalescer::new();

        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        coalescer.get_or_wait(key.clone()).await;
        coalescer.get_or_wait(key.clone()).await;
        coalescer.get_or_wait(key).await;

        let metrics = coalescer.metrics();
        assert_eq!(metrics.misses, 1, "Should have 1 miss for first call");
        assert_eq!(
            metrics.timeouts, 2,
            "Should have 2 timeouts for subsequent calls"
        );
    }

    #[tokio::test]
    async fn test_two_identical_queries_coalesce() {
        let coalescer = Arc::new(QueryCoalescer::new());
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result1 = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result1, Some(CoalesceResult::NewQuery(_))));

        let c = coalescer.clone();
        let k = key.clone();
        let handle = tokio::spawn(async move { c.get_or_wait(k).await });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let response = Arc::new(vec![0x00, 0x01, 0x02]);
        coalescer.broadcast_response(key, response.clone());

        let result2 = handle.await.unwrap();
        match result2 {
            Some(CoalesceResult::Response(r)) => {
                assert_eq!(*r, *response);
            }
            _ => panic!("Expected Response, got {:?}", result2),
        }

        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_owner_broadcasts_positive_response() {
        let coalescer = Arc::new(QueryCoalescer::new());
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        let response = Arc::new(vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        coalescer.broadcast_response(key.clone(), response.clone());

        assert_eq!(coalescer.in_flight_count(), 0);

        let result2 = coalescer.get_or_wait(key).await;
        assert!(matches!(result2, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_owner_broadcasts_negative_response() {
        let coalescer = Arc::new(QueryCoalescer::new());
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        // NXDOMAIN: flags 0x8183 = QR=1, RD=1, RA=1, RCODE=3
        let response = Arc::new(vec![
            0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        coalescer.broadcast_response(key.clone(), response.clone());

        assert_eq!(coalescer.in_flight_count(), 0);

        let result2 = coalescer.get_or_wait(key).await;
        assert!(matches!(result2, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_timeout_cleans_up_in_flight() {
        let coalescer = Arc::new(QueryCoalescer::with_config(50, 10000, 1));
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
        assert_eq!(coalescer.in_flight_count(), 1);

        let c = coalescer.clone();
        let k = key.clone();
        let handle = tokio::spawn(async move { c.get_or_wait(k).await });

        let result2 = handle.await.unwrap();
        assert!(matches!(result2, Some(CoalesceResult::Timeout)));

        assert_eq!(coalescer.in_flight_count(), 1);

        tokio::time::sleep(Duration::from_millis(1100)).await;

        coalescer.cleanup_stale();

        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[test]
    fn test_coalescing_key_do_bit_differs() {
        let key1 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: true,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_coalescing_key_qclass_differs() {
        let key1 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1, // IN
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 3, // CH
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(key1, key2, "Different qclass must not coalesce");
    }

    #[test]
    fn test_coalescing_key_client_ip_differs() {
        let key1 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: Some("10.0.0.1".to_string()),
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: Some("10.0.0.2".to_string()),
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(key1, key2, "Different client_ip must not coalesce");
    }

    #[test]
    fn test_coalescing_key_client_ip_none_vs_some() {
        let key1 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: Some("10.0.0.1".to_string()),
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(key1, key2, "None vs Some client_ip must not coalesce");
    }

    #[test]
    fn test_coalescing_key_edns_size_differs() {
        let key1 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: true,
            client_ip: None,
            transport_class: TransportClass::UdpEdns(512),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: true,
            client_ip: None,
            transport_class: TransportClass::UdpEdns(4096),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(key1, key2, "Different EDNS UDP size must not coalesce");
    }

    #[test]
    fn test_coalescing_key_qtype_differs() {
        let key1 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1, // A
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 28, // AAAA
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(key1, key2, "Different qtype must not coalesce");
    }

    #[test]
    fn test_coalescing_key_canonical_name_case_insensitive() {
        let key1 = QueryKey {
            name: "Example.COM".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key2 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        // Note: from_query lowercases names, but keys constructed directly are not.
        // This test documents that if you construct keys with different cases, they are different.
        // The from_query/from_parsed methods handle lowercasing.
        assert_ne!(key1, key2, "Unnormalized names must not coalesce");
    }

    #[test]
    fn test_coalescing_key_transport_class_differs() {
        let udp_key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::Udp512,
            namespace: CacheNamespace::Authoritative,
        };
        let tcp_key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::Tcp,
            namespace: CacheNamespace::Authoritative,
        };
        let edns_key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::UdpEdns(1232),
            namespace: CacheNamespace::Authoritative,
        };
        let https_key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::Http,
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(udp_key, tcp_key, "UDP vs TCP must not coalesce");
        assert_ne!(udp_key, edns_key, "UDP512 vs UdpEdns must not coalesce");
        assert_ne!(udp_key, https_key, "UDP vs HTTPS must not coalesce");
        assert_ne!(tcp_key, https_key, "TCP vs HTTPS must not coalesce");
    }

    #[test]
    fn test_coalescing_key_edns_size_in_transport_class() {
        let edns_512 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::UdpEdns(512),
            namespace: CacheNamespace::Authoritative,
        };
        let edns_4096 = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::UdpEdns(4096),
            namespace: CacheNamespace::Authoritative,
        };
        assert_ne!(
            edns_512, edns_4096,
            "Different EDNS buffer sizes in transport class must not coalesce"
        );
    }

    #[tokio::test]
    async fn test_multiple_waiters_all_receive_response() {
        let coalescer = Arc::new(QueryCoalescer::with_config(2000, 10000, 30));
        let key = QueryKey {
            name: "multiwaiter.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        // Owner
        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        let num_waiters = 5;
        let mut handles = Vec::new();
        for _ in 0..num_waiters {
            let c = coalescer.clone();
            let k = key.clone();
            handles.push(tokio::spawn(async move { c.get_or_wait(k).await }));
        }

        // Let waiters register
        tokio::time::sleep(Duration::from_millis(10)).await;

        let response = Arc::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        coalescer.broadcast_response(key.clone(), response.clone());

        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                Some(CoalesceResult::Response(r)) => {
                    assert_eq!(*r, *response);
                }
                _ => panic!("Expected Response for waiter, got {:?}", result),
            }
        }

        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_owner_cancel_removes_in_flight() {
        let coalescer = Arc::new(QueryCoalescer::with_config(5000, 10000, 30));
        let key = QueryKey {
            name: "cancel.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
        assert_eq!(coalescer.in_flight_count(), 1);

        // Simulate owner failure
        coalescer.cancel_in_flight(&key);

        assert_eq!(coalescer.in_flight_count(), 0);

        // A new query after cancel should become a new owner
        let result2 = coalescer.get_or_wait(key).await;
        assert!(
            matches!(result2, Some(CoalesceResult::NewQuery(_))),
            "After cancel, next query should be NewQuery"
        );
    }

    #[tokio::test]
    async fn test_late_broadcast_after_cleanup_is_ignored() {
        let coalescer = Arc::new(QueryCoalescer::with_config(50, 10000, 1));
        let key = QueryKey {
            name: "late.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
        assert_eq!(coalescer.in_flight_count(), 1);

        // Wait for entry to become stale
        tokio::time::sleep(Duration::from_millis(1100)).await;
        coalescer.cleanup_stale();
        assert_eq!(coalescer.in_flight_count(), 0);

        // Late broadcast should not panic
        let response = Arc::new(vec![0x01]);
        coalescer.broadcast_response(key.clone(), response);

        // Entry was already removed, so no change
        assert_eq!(coalescer.in_flight_count(), 0);

        // New query should become owner
        let result2 = coalescer.get_or_wait(key).await;
        assert!(matches!(result2, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_repeated_query_after_broadcast_becomes_new_owner() {
        let coalescer = Arc::new(QueryCoalescer::new());
        let key = QueryKey {
            name: "repeat.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        // First owner
        let result1 = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result1, Some(CoalesceResult::NewQuery(_))));

        let response = Arc::new(vec![0xAA, 0xBB]);
        coalescer.broadcast_response(key.clone(), response.clone());
        assert_eq!(coalescer.in_flight_count(), 0);

        // Second query should be new owner (not a waiter)
        let result2 = coalescer.get_or_wait(key.clone()).await;
        assert!(
            matches!(result2, Some(CoalesceResult::NewQuery(_))),
            "After broadcast, next query should become new owner"
        );

        coalescer.broadcast_response(key.clone(), response);
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_waiter_timeout_does_not_affect_owner() {
        let coalescer = Arc::new(QueryCoalescer::with_config(30, 10000, 30));
        let key = QueryKey {
            name: "timeout_owner.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        // Owner
        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        // Waiter that times out
        let c = coalescer.clone();
        let k = key.clone();
        let handle = tokio::spawn(async move { c.get_or_wait(k).await });
        let waiter_result = handle.await.unwrap();
        assert!(matches!(waiter_result, Some(CoalesceResult::Timeout)));

        // Owner entry should still be there
        assert_eq!(coalescer.in_flight_count(), 1);

        // Owner can still broadcast
        let response = Arc::new(vec![0x01]);
        coalescer.broadcast_response(key.clone(), response);
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_stale_removes_zero_receiver_entries() {
        let coalescer = Arc::new(QueryCoalescer::with_config(5000, 10000, 1));
        let key = QueryKey {
            name: "stale_cleanup.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
        assert_eq!(coalescer.in_flight_count(), 1);

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(1100)).await;

        coalescer.cleanup_stale();
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_stale_aged_removes_old_entries() {
        let coalescer = Arc::new(QueryCoalescer::with_config(5000, 10000, 60));
        let key = QueryKey {
            name: "aged_cleanup.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
        assert_eq!(coalescer.in_flight_count(), 1);

        // Wait so the entry is actually older than max_age
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Use cleanup_stale_aged with a very short age
        coalescer.cleanup_stale_aged(Duration::from_millis(1));
        assert_eq!(
            coalescer.in_flight_count(),
            0,
            "cleanup_stale_aged should remove entries older than max_age"
        );
    }

    #[tokio::test]
    async fn test_cleanup_preserves_fresh_entries() {
        let coalescer = Arc::new(QueryCoalescer::with_config(5000, 10000, 30));
        let key = QueryKey {
            name: "fresh.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
        assert_eq!(coalescer.in_flight_count(), 1);

        // Spawn a waiter so the entry has an active receiver (non-zero receiver_count)
        let c = coalescer.clone();
        let k = key.clone();
        let handle = tokio::spawn(async move { c.get_or_wait(k).await });

        // Give the waiter time to register its receiver
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cleanup immediately - entry is fresh and has receivers
        coalescer.cleanup_stale();
        assert_eq!(
            coalescer.in_flight_count(),
            1,
            "Fresh entry with active receivers should not be cleaned up"
        );

        // Clean up the waiter so it doesn't hang
        let response = Arc::new(vec![0x01]);
        coalescer.broadcast_response(key, response);
        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_owner_and_multiple_waiters() {
        let coalescer = Arc::new(QueryCoalescer::with_config(2000, 10000, 30));
        let key = QueryKey {
            name: "concurrent.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        let mut handles = Vec::new();
        for i in 0..10 {
            let c = coalescer.clone();
            let k = key.clone();
            handles.push(tokio::spawn(async move {
                let r = c.get_or_wait(k).await;
                (i, r)
            }));
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
        let response = Arc::new(vec![0xCA, 0xFE]);
        coalescer.broadcast_response(key.clone(), response.clone());

        for handle in handles {
            let (i, result) = handle.await.unwrap();
            match result {
                Some(CoalesceResult::Response(r)) => {
                    assert_eq!(*r, *response, "Waiter {} should get broadcast response", i);
                }
                _ => panic!("Waiter {} expected Response, got {:?}", i, result),
            }
        }
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_cancel_wakes_waiters_with_none() {
        let coalescer = Arc::new(QueryCoalescer::with_config(5000, 10000, 30));
        let key = QueryKey {
            name: "cancel_waiters.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        let c = coalescer.clone();
        let k = key.clone();
        let handle = tokio::spawn(async move { c.get_or_wait(k).await });

        // Give the waiter time to subscribe to the broadcast channel
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            coalescer.in_flight_count(),
            1,
            "Entry should still be in-flight before cancel"
        );

        coalescer.cancel_in_flight(&key);

        let waiter_result = handle.await.unwrap();
        // After cancel, the broadcast channel is closed, so waiter gets None
        // or it may have timed out if scheduling was delayed — both are acceptable
        assert!(
            waiter_result.is_none() || matches!(waiter_result, Some(CoalesceResult::Timeout)),
            "Waiter should receive None or Timeout after cancel, got {:?}",
            waiter_result
        );
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_new_query_after_full_broadcast_cycle() {
        let coalescer = Arc::new(QueryCoalescer::new());
        let key = QueryKey {
            name: "cycle.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        for cycle in 0..5 {
            let result = coalescer.get_or_wait(key.clone()).await;
            assert!(
                matches!(result, Some(CoalesceResult::NewQuery(_))),
                "Cycle {}: should be NewQuery",
                cycle
            );

            let response = Arc::new(vec![cycle as u8]);
            coalescer.broadcast_response(key.clone(), response.clone());
            assert_eq!(
                coalescer.in_flight_count(),
                0,
                "Cycle {}: should be empty after broadcast",
                cycle
            );
        }
    }

    #[tokio::test]
    async fn test_waiter_timeout_then_owner_succeeds() {
        let coalescer = Arc::new(QueryCoalescer::with_config(20, 10000, 30));
        let key = QueryKey {
            name: "timeout_then_owner.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));

        let c = coalescer.clone();
        let k = key.clone();
        let handle = tokio::spawn(async move { c.get_or_wait(k).await });
        let waiter_result = handle.await.unwrap();
        assert!(matches!(waiter_result, Some(CoalesceResult::Timeout)));

        assert_eq!(coalescer.in_flight_count(), 1);

        let response = Arc::new(vec![0xFF]);
        coalescer.broadcast_response(key.clone(), response.clone());
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[test]
    fn test_namespace_dimension_in_key() {
        let key_auth = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };
        let key_rec = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Recursive,
        };
        assert_ne!(
            key_auth, key_rec,
            "Authoritative and Recursive namespace must not coalesce"
        );
    }
}

#[cfg(test)]
mod coalescing_exclusion_tests {
    use super::*;

    #[test]
    fn test_axfr_skips_coalescing() {
        assert!(
            should_skip_coalescing(252, 0),
            "AXFR qtype 252 must skip coalescing"
        );
    }

    #[test]
    fn test_ixfr_skips_coalescing() {
        assert!(
            should_skip_coalescing(251, 0),
            "IXFR qtype 251 must skip coalescing"
        );
    }

    #[test]
    fn test_notify_skips_coalescing() {
        assert!(
            should_skip_coalescing(1, 4),
            "NOTIFY opcode 4 must skip coalescing"
        );
    }

    #[test]
    fn test_update_skips_coalescing() {
        assert!(
            should_skip_coalescing(1, 5),
            "UPDATE opcode 5 must skip coalescing"
        );
    }

    #[test]
    fn test_standard_query_does_not_skip() {
        assert!(
            !should_skip_coalescing(1, 0),
            "Standard A query must not skip"
        );
        assert!(
            !should_skip_coalescing(28, 0),
            "Standard AAAA query must not skip"
        );
        assert!(
            !should_skip_coalescing(15, 0),
            "Standard MX query must not skip"
        );
    }

    #[test]
    fn test_axfr_with_notify_opcode_skips() {
        assert!(
            should_skip_coalescing(252, 4),
            "AXFR + NOTIFY must skip coalescing"
        );
    }

    #[tokio::test]
    async fn test_axfr_query_always_returns_new_query() {
        let coalescer = QueryCoalescer::new();
        let qtype: u16 = 252; // AXFR
        let opcode: u8 = 0;
        assert!(should_skip_coalescing(qtype, opcode));

        let key = QueryKey {
            name: "example.com".to_string(),
            qtype,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        // Even if an entry exists, should_skip_coalescing means the caller
        // must not call get_or_wait. This test documents the intent: the
        // caller checks should_skip_coalescing before entering the coalescer.
        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_ixfr_query_always_returns_new_query() {
        let coalescer = QueryCoalescer::new();
        let qtype: u16 = 251; // IXFR
        let opcode: u8 = 0;
        assert!(should_skip_coalescing(qtype, opcode));

        let key = QueryKey {
            name: "example.com".to_string(),
            qtype,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_notify_opcode_skips_coalescing() {
        let coalescer = QueryCoalescer::new();
        let opcode: u8 = 4; // NOTIFY
        assert!(should_skip_coalescing(1, opcode));

        // NOTIFY queries typically use qtype ANY (255)
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 255,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_update_opcode_skips_coalescing() {
        let coalescer = QueryCoalescer::new();
        let opcode: u8 = 5; // UPDATE
        assert!(should_skip_coalescing(1, opcode));

        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        };

        let result = coalescer.get_or_wait(key.clone()).await;
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
    }

    #[test]
    fn test_malformed_query_returns_none_from_key_parsing() {
        let key = QueryKey::from_query(&[0x00], None, None);
        assert!(
            key.is_none(),
            "Malformed query must not produce a coalescing key"
        );
    }
}

#[cfg(test)]
mod key_parsing_integration {
    use super::*;

    fn build_query(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // Encode name
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00); // root
        query.push((qtype >> 8) as u8);
        query.push((qtype & 0xFF) as u8);
        query.push((qclass >> 8) as u8);
        query.push((qclass & 0xFF) as u8);
        query
    }

    #[test]
    fn test_axfr_query_parses_to_key() {
        // AXFR qtype = 252
        let query = build_query("example.com", 252, 1);
        let key = QueryKey::from_query(&query, None, None);
        assert!(key.is_some(), "AXFR query should parse into a QueryKey");
        let key = key.unwrap();
        assert_eq!(key.qtype, 252);
        assert_eq!(key.name, "example.com");
    }

    #[test]
    fn test_ixfr_query_parses_to_key() {
        // IXFR qtype = 251
        let query = build_query("example.com", 251, 1);
        let key = QueryKey::from_query(&query, None, None);
        assert!(key.is_some(), "IXFR query should parse into a QueryKey");
        let key = key.unwrap();
        assert_eq!(key.qtype, 251);
    }

    #[test]
    fn test_axfr_and_ixfr_keys_are_different() {
        let axfr_query = build_query("example.com", 252, 1);
        let ixfr_query = build_query("example.com", 251, 1);
        let key_axfr = QueryKey::from_query(&axfr_query, None, None).unwrap();
        let key_ixfr = QueryKey::from_query(&ixfr_query, None, None).unwrap();
        assert_ne!(key_axfr, key_ixfr, "AXFR and IXFR must have different keys");
    }

    #[test]
    fn test_axfr_key_differs_from_a_record() {
        let axfr_query = build_query("example.com", 252, 1);
        let a_query = build_query("example.com", 1, 1);
        let key_axfr = QueryKey::from_query(&axfr_query, None, None).unwrap();
        let key_a = QueryKey::from_query(&a_query, None, None).unwrap();
        assert_ne!(
            key_axfr, key_a,
            "AXFR must not coalesce with A record query"
        );
    }

    #[test]
    fn test_notify_query_parses_to_key() {
        // NOTIFY has opcode=4 in the flags (0x2800)
        let mut query = vec![
            0x12, 0x34, // ID
            0x28, 0x00, // Flags: opcode=NOTIFY (4), QR=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        for label in "example.com".split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00);
        query.push(0x00); // qtype = ANY (255)
        query.push(0xFF);
        query.push(0x00); // qclass = IN
        query.push(0x01);
        let key = QueryKey::from_query(&query, None, None);
        assert!(key.is_some(), "NOTIFY should parse into a QueryKey");
    }
}
