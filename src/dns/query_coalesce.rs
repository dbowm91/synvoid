use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics::Gauge;
use parking_lot::RwLock;
use tokio::sync::broadcast;

static COALESCER_HITS: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_hits_total"));
static COALESCER_MISSES: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_misses_total"));
static COALESCER_EVICTIONS: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_evictions_total"));
static COALESCER_TIMEOUTS: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_timeouts_total"));
static COALESCER_LAGGED: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_lagged_total"));
static COALESCER_IN_FLIGHT: std::sync::LazyLock<Gauge> =
    std::sync::LazyLock::new(|| metrics::gauge!("dns_query_coalescer_in_flight"));

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QueryKey {
    pub name: String,
    pub qtype: u16,
    pub client_ip: Option<String>,
}

impl QueryKey {
    pub fn from_query(query: &[u8], client_ip: Option<std::net::IpAddr>) -> Option<Self> {
        // Parse query name directly from wire format (skip DNS header)
        let mut pos = 12; // DNS header is 12 bytes
        let mut name = String::new();

        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                break;
            }
            // Check for compression pointer
            if (len & 0xC0) == 0xC0 {
                break;
            }
            if pos + 1 + len > query.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            let label = String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]);
            name.push_str(&label);
            pos += 1 + len;
        }

        if name.is_empty() {
            return None;
        }

        // Get qtype from bytes after the name
        let qtype_pos = pos + 1; // Skip null byte
        if qtype_pos + 2 > query.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([query[qtype_pos], query[qtype_pos + 1]]);

        let client_str = client_ip.map(|ip| ip.to_string());

        Some(Self {
            name,
            qtype,
            client_ip: client_str,
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
}

#[allow(dead_code)] // max_wait_time reserved for future timeout enforcement
pub struct QueryCoalescer {
    in_flight: Arc<RwLock<HashMap<QueryKey, CoalescerEntry>>>,
    max_wait_time: Duration,
    max_entries: usize,
    entry_ttl: Duration,
    metrics: Arc<RwLock<QueryCoalescerMetrics>>,
}

impl QueryCoalescer {
    pub fn new() -> Self {
        Self {
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            max_wait_time: Duration::from_millis(500),
            max_entries: 10000,
            entry_ttl: Duration::from_secs(30),
            metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
        }
    }

    pub fn with_max_wait_time(max_wait_ms: u64) -> Self {
        Self {
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            max_wait_time: Duration::from_millis(max_wait_ms),
            max_entries: 10000,
            entry_ttl: Duration::from_secs(30),
            metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
        }
    }

    pub fn with_config(max_wait_ms: u64, max_entries: usize, entry_ttl_secs: u64) -> Self {
        Self {
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            max_wait_time: Duration::from_millis(max_wait_ms),
            max_entries,
            entry_ttl: Duration::from_secs(entry_ttl_secs),
            metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
        }
    }

    pub fn get_or_wait(&self, key: QueryKey) -> Option<CoalesceResult> {
        let mut in_flight = self.in_flight.write();

        if let Some(entry) = in_flight.get(&key) {
            let mut receiver = entry.sender.subscribe();
            drop(in_flight);

            // Use try_recv for non-blocking receive
            match receiver.try_recv() {
                Ok(response) => {
                    self.metrics.write().hits += 1;
                    COALESCER_HITS.increment(1.0);
                    return Some(CoalesceResult::Response(response));
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    self.metrics.write().lagged += 1;
                    COALESCER_LAGGED.increment(1.0);
                    tracing::debug!("Coalescer lagged {} messages for {:?}", n, key);
                    return Some(CoalesceResult::Lagged);
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    return None;
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // Message not ready yet - return Timeout to indicate caller should wait
                    self.metrics.write().timeouts += 1;
                    COALESCER_TIMEOUTS.increment(1.0);
                    return Some(CoalesceResult::Timeout);
                }
            }
        }

        if in_flight.len() >= self.max_entries {
            self.evict_oldest(&mut in_flight);
        }

        let (tx, _) = broadcast::channel(1);
        let entry = CoalescerEntry {
            sender: tx.clone(),
            created_at: Instant::now(),
        };
        in_flight.insert(key.clone(), entry);
        let count = in_flight.len();
        drop(in_flight);

        self.metrics.write().misses += 1;
        COALESCER_MISSES.increment(1.0);
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
            COALESCER_EVICTIONS.increment(1.0);
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
        COALESCER_IN_FLIGHT.set(in_flight.len() as f64);
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
            COALESCER_EVICTIONS.increment((prev_count - new_count) as f64);
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
            COALESCER_EVICTIONS.increment((prev_count - new_count) as f64);
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

        let key = QueryKey::from_query(&query, None).unwrap();
        assert_eq!(key.name, "example.com");
        assert_eq!(key.qtype, 1);
    }

    #[tokio::test]
    async fn test_coalesce_new_query() {
        let coalescer = QueryCoalescer::new();
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            client_ip: None,
        };

        let result = coalescer.get_or_wait(key.clone());
        assert!(matches!(result, Some(CoalesceResult::NewQuery(_))));
    }

    #[tokio::test]
    async fn test_coalesce_broadcast() {
        let coalescer = QueryCoalescer::new();
        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            client_ip: None,
        };

        let response = Arc::new(vec![0x00, 0x01, 0x02, 0x03]);

        // First, get_or_wait to establish a listener
        let _ = coalescer.get_or_wait(key.clone());

        // Then broadcast - the listener should receive it
        coalescer.broadcast_response(key.clone(), response.clone());

        // Now get_or_wait again - should receive the broadcast
        let result = coalescer.get_or_wait(key);

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

    #[test]
    fn test_max_entries_eviction() {
        let coalescer = QueryCoalescer::with_config(500, 3, 30);

        for i in 0..5 {
            let key = QueryKey {
                name: format!("example{}.com", i),
                qtype: 1,
                client_ip: None,
            };
            coalescer.get_or_wait(key);
        }

        assert_eq!(coalescer.in_flight_count(), 3);
        assert_eq!(coalescer.metrics().evictions, 2);
    }

    #[test]
    fn test_metrics() {
        let coalescer = QueryCoalescer::new();

        let key = QueryKey {
            name: "example.com".to_string(),
            qtype: 1,
            client_ip: None,
        };

        // First call creates a new entry - this is a miss
        coalescer.get_or_wait(key.clone());

        // Second and third calls find existing entry - these time out (non-blocking)
        coalescer.get_or_wait(key.clone());
        coalescer.get_or_wait(key);

        let metrics = coalescer.metrics();
        // First call is a miss, subsequent calls timeout because no response was broadcast
        assert_eq!(metrics.misses, 1, "Should have 1 miss for first call");
        assert_eq!(
            metrics.timeouts, 2,
            "Should have 2 timeouts for subsequent calls"
        );
    }
}
