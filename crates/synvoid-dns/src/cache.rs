use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHasher;
use moka::sync::Cache;
use parking_lot::RwLock;

use super::metrics::DnsMetrics;
use super::parsed_query::ParsedDnsQuery;
use super::server::RecordType;

/// Reasons for cache invalidation, tracked as per-reason counters for operational visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidationReason {
    /// Zone files loaded from disk
    ZoneLoad,
    /// Zones restored from SQLite persistence
    ZoneLoadFromStore,
    /// A DNS record was inserted into a zone
    RecordAdd,
    /// A zone was removed from in-memory store
    ZoneDelete,
    /// Client RFC 2136 dynamic update modified a zone
    DynamicUpdate,
    /// Peer notified this server that a zone changed
    NotifyReceived,
    /// Explicit full cache flush (operator-triggered)
    ManualFlush,
    /// DNSSEC key rollover started or completed
    DnssecKeyRollover,
    /// RPZ zone removed (affects any DNS name, full wipe needed)
    RpzZoneRemoval,
    /// Full zone transfer (AXFR) received from a primary.
    ZoneTransferAxfr,
    /// Incremental zone transfer (IXFR) received from a primary.
    ZoneTransferIxfr,
}

impl InvalidationReason {
    /// Returns the Prometheus metric label for this reason.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::ZoneLoad => "zone_load",
            Self::ZoneLoadFromStore => "zone_load_from_store",
            Self::RecordAdd => "record_add",
            Self::ZoneDelete => "zone_delete",
            Self::DynamicUpdate => "dynamic_update",
            Self::NotifyReceived => "notify_received",
            Self::ManualFlush => "manual_flush",
            Self::DnssecKeyRollover => "dnssec_key_rollover",
            Self::RpzZoneRemoval => "rpz_zone_removal",
            Self::ZoneTransferAxfr => "zone_transfer_axfr",
            Self::ZoneTransferIxfr => "zone_transfer_ixfr",
        }
    }
}

impl fmt::Display for InvalidationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_label())
    }
}

/// Classifies the transport/EDNS response-shape class for cache keying.
///
/// Different transports and EDNS configurations can produce different wire-format
/// responses (e.g., UDP with 512-byte limit vs. TCP with no limit, or DO-bit
/// differences). The transport class captures the dimensions that affect response shape.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub enum TransportClass {
    /// UDP with standard 512-byte limit (no EDNS)
    Udp512,
    /// UDP with EDNS payload size (includes 1232-byte default)
    UdpEdns(u16),
    /// TCP transport (no size limit)
    Tcp,
    /// DNS-over-HTTPS
    Http,
    /// DNS-over-QUIC
    Quic,
}

impl Default for TransportClass {
    fn default() -> Self {
        Self::Udp512
    }
}

impl TransportClass {
    /// Derive transport class from EDNS OPT record context.
    ///
    /// When a query includes an EDNS OPT record, the CLASS field of the OPT RR
    /// contains the sender's UDP payload size. This value determines the maximum
    /// response size that fits without fragmentation, so different values produce
    /// different response shapes and must not share cache entries.
    ///
    /// If `has_edns` is false, returns `Udp512` (legacy 512-byte limit).
    pub fn from_edns(has_edns: bool, udp_payload_size: u16) -> Self {
        if has_edns {
            Self::UdpEdns(udp_payload_size)
        } else {
            Self::Udp512
        }
    }
}

/// Separates authoritative and recursive cache namespaces to prevent cross-contamination.
///
/// Authoritative cache entries come from local zone data. Recursive cache entries
/// come from upstream resolvers. These must never share cache key space.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub enum CacheNamespace {
    /// Local authoritative zone data
    Authoritative,
    /// Recursive resolution results from upstream
    Recursive,
}

impl Default for CacheNamespace {
    fn default() -> Self {
        Self::Authoritative
    }
}

/// DNS cache key covering all output-affecting dimensions.
///
/// Two queries that could produce different wire-format responses MUST have
/// different cache keys. Dimensions:
/// - `qname` — canonical (lowercased) query name
/// - `qtype` — DNS record type
/// - `qclass` — DNS class (default IN=1)
/// - `dnssec_ok` — DO bit affects RRSIG presence in response
/// - `client_subnet` — ECS option affects answer content
/// - `transport_class` — transport/EDNS affects TC flag and truncation
/// - `namespace` — separates authoritative vs recursive cache entries
#[derive(Clone, Debug, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec_ok: bool,
    pub client_subnet: Option<IpAddr>,
    pub transport_class: TransportClass,
    pub namespace: CacheNamespace,
}

impl CacheKey {
    /// Full constructor with all dimensions.
    pub fn new(qname: String, qtype: RecordType, client_subnet: Option<IpAddr>) -> Self {
        Self {
            qname,
            qtype: qtype.into(),
            qclass: 1, // IN
            dnssec_ok: false,
            client_subnet,
            transport_class: TransportClass::default(),
            namespace: CacheNamespace::Authoritative,
        }
    }

    /// Build a cache key from a parsed query for authoritative responses.
    pub fn from_parsed_authoritative(
        parsed: &ParsedDnsQuery<'_>,
        client_ip: IpAddr,
        transport_class: TransportClass,
    ) -> Self {
        CacheKey {
            qname: parsed.qname.clone(),
            qtype: parsed.qtype,
            qclass: parsed.qclass,
            dnssec_ok: parsed.dnssec_ok,
            client_subnet: Some(client_ip),
            transport_class,
            namespace: CacheNamespace::Authoritative,
        }
    }

    /// Build a cache key from a parsed query for recursive responses.
    pub fn from_parsed_recursive(
        parsed: &ParsedDnsQuery<'_>,
        client_ip: IpAddr,
        transport_class: TransportClass,
    ) -> Self {
        CacheKey {
            qname: parsed.qname.clone(),
            qtype: parsed.qtype,
            qclass: parsed.qclass,
            dnssec_ok: parsed.dnssec_ok,
            client_subnet: Some(client_ip),
            transport_class,
            namespace: CacheNamespace::Recursive,
        }
    }

    /// Construct with DNSSEC OK bit set.
    pub fn with_dnssec(qname: String, qtype: RecordType, client_subnet: Option<IpAddr>) -> Self {
        Self {
            dnssec_ok: true,
            ..Self::new(qname, qtype, client_subnet)
        }
    }

    /// Construct for the recursive namespace.
    pub fn recursive(qname: String, qtype: RecordType, client_subnet: Option<IpAddr>) -> Self {
        Self {
            namespace: CacheNamespace::Recursive,
            ..Self::new(qname, qtype, client_subnet)
        }
    }

    /// Construct with explicit class.
    pub fn with_class(
        qname: String,
        qtype: RecordType,
        qclass: u16,
        client_subnet: Option<IpAddr>,
    ) -> Self {
        Self {
            qclass,
            ..Self::new(qname, qtype, client_subnet)
        }
    }

    /// Construct with transport class.
    pub fn with_transport(
        qname: String,
        qtype: RecordType,
        client_subnet: Option<IpAddr>,
        transport_class: TransportClass,
    ) -> Self {
        Self {
            transport_class,
            ..Self::new(qname, qtype, client_subnet)
        }
    }

    /// Canonicalize qname to lowercase for case-insensitive lookup.
    pub fn canonicalize(&mut self) {
        self.qname = self.qname.to_lowercase();
    }
}

#[derive(Clone)]
pub struct CachedResponse {
    pub data: Arc<Vec<u8>>,
    pub ttl: Duration,
    pub cached_at: Instant,
    pub fingerprint: u64,
    pub source_ip: Option<IpAddr>,
    pub is_dnssec_signed: bool,
}

/// Aggregate metrics for cache operations.
#[derive(Debug)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub stale_hits: AtomicU64,
    pub negative_hits: AtomicU64,
    pub misses: AtomicU64,
    pub insertions: AtomicU64,
    pub invalidations: AtomicU64,
    pub poisoned_rejections: AtomicU64,
    pub size_rejections: AtomicU64,
    /// Per-reason invalidation counters. Key is `InvalidationReason::as_label()`.
    pub invalidations_by_reason: RwLock<HashMap<String, AtomicU64>>,
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self {
            hits: AtomicU64::new(0),
            stale_hits: AtomicU64::new(0),
            negative_hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            insertions: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
            poisoned_rejections: AtomicU64::new(0),
            size_rejections: AtomicU64::new(0),
            invalidations_by_reason: RwLock::new(HashMap::new()),
        }
    }
}

impl Clone for CacheMetrics {
    fn clone(&self) -> Self {
        let reason_snapshot = {
            let src = self.invalidations_by_reason.read();
            let mut dst = HashMap::new();
            for (k, v) in src.iter() {
                dst.insert(k.clone(), AtomicU64::new(v.load(Ordering::Relaxed)));
            }
            dst
        };
        Self {
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
            stale_hits: AtomicU64::new(self.stale_hits.load(Ordering::Relaxed)),
            negative_hits: AtomicU64::new(self.negative_hits.load(Ordering::Relaxed)),
            misses: AtomicU64::new(self.misses.load(Ordering::Relaxed)),
            insertions: AtomicU64::new(self.insertions.load(Ordering::Relaxed)),
            invalidations: AtomicU64::new(self.invalidations.load(Ordering::Relaxed)),
            poisoned_rejections: AtomicU64::new(self.poisoned_rejections.load(Ordering::Relaxed)),
            size_rejections: AtomicU64::new(self.size_rejections.load(Ordering::Relaxed)),
            invalidations_by_reason: RwLock::new(reason_snapshot),
        }
    }
}

#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<InnerDnsCache>,
}

struct InnerDnsCache {
    cache: Cache<CacheKey, CachedResponse>,
    qname_index: RwLock<HashMap<String, HashSet<CacheKey>>>,
    max_ttl: Duration,
    min_ttl: Duration,
    max_entry_size: usize,
    cache_fingerprints: RwLock<HashMap<String, Vec<(u64, Instant)>>>,
    enable_source_validation: bool,
    enable_fingerprinting: bool,
    max_fingerprints_per_name: usize,
    max_capacity: usize,
    serve_stale_enabled: bool,
    serve_stale_max_stale: Duration,
    stale_served_count: AtomicU64,
    max_stale_count: u64,
    confirmation_threshold: usize,
    metrics: CacheMetrics,
    /// Optional DnsMetrics for bridging cache counters to the Prometheus-exported metrics.
    dns_metrics: Option<Arc<DnsMetrics>>,
}

impl DnsCache {
    pub fn new(capacity: usize, max_ttl_secs: u64, min_ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity as u64)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .weigher(|_key: &CacheKey, value: &CachedResponse| {
                u32::try_from(value.data.len()).unwrap_or(u32::MAX)
            })
            .build();

        Self {
            inner: Arc::new(InnerDnsCache {
                cache,
                qname_index: RwLock::new(HashMap::new()),
                max_ttl: Duration::from_secs(max_ttl_secs),
                min_ttl: Duration::from_secs(min_ttl_secs),
                max_entry_size: 65535,
                cache_fingerprints: RwLock::new(HashMap::new()),
                enable_source_validation: true,
                enable_fingerprinting: true,
                max_fingerprints_per_name: 10,
                max_capacity: capacity,
                serve_stale_enabled: false,
                serve_stale_max_stale: Duration::from_secs(86400),
                stale_served_count: AtomicU64::new(0),
                max_stale_count: 100,
                confirmation_threshold: 3,
                metrics: CacheMetrics::default(),
                dns_metrics: None,
            }),
        }
    }

    pub fn with_security(
        capacity: usize,
        max_ttl_secs: u64,
        min_ttl_secs: u64,
        max_entry_size: usize,
        enable_source_validation: bool,
        enable_fingerprinting: bool,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity as u64)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .weigher(|_key: &CacheKey, value: &CachedResponse| {
                u32::try_from(value.data.len()).unwrap_or(u32::MAX)
            })
            .build();

        Self {
            inner: Arc::new(InnerDnsCache {
                cache,
                qname_index: RwLock::new(HashMap::new()),
                max_ttl: Duration::from_secs(max_ttl_secs),
                min_ttl: Duration::from_secs(min_ttl_secs),
                max_entry_size,
                cache_fingerprints: RwLock::new(HashMap::new()),
                enable_source_validation,
                enable_fingerprinting,
                max_fingerprints_per_name: 10,
                max_capacity: capacity,
                serve_stale_enabled: false,
                serve_stale_max_stale: Duration::from_secs(86400),
                stale_served_count: AtomicU64::new(0),
                max_stale_count: 100,
                confirmation_threshold: 3,
                metrics: CacheMetrics::default(),
                dns_metrics: None,
            }),
        }
    }

    pub fn with_serve_stale(
        capacity: usize,
        max_ttl_secs: u64,
        min_ttl_secs: u64,
        serve_stale_enabled: bool,
        serve_stale_max_stale_secs: u64,
        serve_stale_max_stale_count: u64,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity as u64)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .weigher(|_key: &CacheKey, value: &CachedResponse| {
                u32::try_from(value.data.len()).unwrap_or(u32::MAX)
            })
            .build();

        Self {
            inner: Arc::new(InnerDnsCache {
                cache,
                qname_index: RwLock::new(HashMap::new()),
                max_ttl: Duration::from_secs(max_ttl_secs),
                min_ttl: Duration::from_secs(min_ttl_secs),
                max_entry_size: 65535,
                cache_fingerprints: RwLock::new(HashMap::new()),
                enable_source_validation: true,
                enable_fingerprinting: true,
                max_fingerprints_per_name: 10,
                max_capacity: capacity,
                serve_stale_enabled,
                serve_stale_max_stale: Duration::from_secs(serve_stale_max_stale_secs),
                stale_served_count: AtomicU64::new(0),
                max_stale_count: serve_stale_max_stale_count,
                confirmation_threshold: 3,
                metrics: CacheMetrics::default(),
                dns_metrics: None,
            }),
        }
    }

    pub fn compute_fingerprint(data: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = AHasher::default();
        data.hash(&mut hasher);
        hasher.finish()
    }

    /// Attach `DnsMetrics` to bridge internal cache counters to the Prometheus-exported metrics.
    ///
    /// This enables cache operations (get/insert/invalidate/clear) to record into the
    /// query-level `DnsMetrics` counters that are exposed via the admin metrics endpoint.
    pub fn with_metrics(self, metrics: Arc<DnsMetrics>) -> Self {
        // SAFETY: with_metrics is only called during startup before the cache is shared.
        // Arc::try_unwrap should always succeed at that point.
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(inner) => inner,
            Err(_) => panic!("with_metrics called after cache was shared"),
        };
        Self {
            inner: Arc::new(InnerDnsCache {
                dns_metrics: Some(metrics),
                ..inner
            }),
        }
    }

    fn validate_response(&self, key: &CacheKey, data: &[u8]) -> Result<(), CachePoisoningError> {
        let inner = &self.inner;

        if data.len() > inner.max_entry_size {
            inner
                .metrics
                .size_rejections
                .fetch_add(1, Ordering::Relaxed);
            if let Some(ref dm) = inner.dns_metrics {
                dm.record_cache_size_rejection();
            }
            return Err(CachePoisoningError::EntryTooLarge {
                size: data.len(),
                max: inner.max_entry_size,
            });
        }

        if inner.enable_fingerprinting {
            let fingerprint = Self::compute_fingerprint(data);
            // WS6: Key fingerprint by full cache key dimensions (qname+qtype+qclass+dnssec+namespace),
            // not just qname. This prevents A and AAAA for same qname from conflicting.
            let fp_key = Self::fingerprint_key(key);
            let fingerprints = inner.cache_fingerprints.write();

            if let Some(existing) = fingerprints.get(&fp_key) {
                let has_fingerprint = existing.iter().any(|(fp, _)| *fp == fingerprint);
                if existing.len() >= inner.max_fingerprints_per_name {
                    if !has_fingerprint {
                        let fps: Vec<u64> = existing.iter().map(|(fp, _)| *fp).collect();
                        inner
                            .metrics
                            .poisoned_rejections
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(ref dm) = inner.dns_metrics {
                            dm.record_cache_poisoned_rejection();
                        }
                        return Err(CachePoisoningError::FingerprintMismatch {
                            qname: key.qname.clone(),
                            expected: fps,
                            actual: fingerprint,
                        });
                    }
                } else if !existing.is_empty() && !has_fingerprint {
                    let first_fingerprint = existing[0].0;
                    let confirmations = existing
                        .iter()
                        .filter(|(fp, _)| *fp == first_fingerprint)
                        .count();
                    // After confirmation threshold, allow new fingerprints (legitimate zone changes).
                    // Only reject if under threshold — this handles legitimate variance after zone updates.
                    if confirmations < inner.confirmation_threshold {
                        tracing::warn!(
                            "Cache poisoning suspected for {} (unconfirmed fingerprint: {}) - blocking response",
                            key.qname,
                            fingerprint
                        );
                        inner
                            .metrics
                            .poisoned_rejections
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(ref dm) = inner.dns_metrics {
                            dm.record_cache_poisoned_rejection();
                        }
                        return Err(CachePoisoningError::PotentialPoisoning {
                            qname: key.qname.clone(),
                            new_fingerprint: fingerprint,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Build a fingerprint key from full cache key dimensions.
    /// Format: "qname|qtype|qclass|dnssec|namespace"
    fn fingerprint_key(key: &CacheKey) -> String {
        format!(
            "{}|{}|{}|{}|{:?}",
            key.qname, key.qtype, key.qclass, key.dnssec_ok, key.namespace
        )
    }

    fn record_fingerprint(&self, key: &CacheKey, data: &[u8]) {
        let inner = &self.inner;

        if !inner.enable_fingerprinting {
            return;
        }

        let fingerprint = Self::compute_fingerprint(data);
        let fp_key = Self::fingerprint_key(key);
        let now = Instant::now();
        let mut fingerprints = inner.cache_fingerprints.write();

        let entry = fingerprints.entry(fp_key).or_default();

        // Evict entries older than 1 hour
        let max_age = Duration::from_secs(3600);
        entry.retain(|(_, ts)| now.duration_since(*ts) < max_age);

        if !entry.iter().any(|(fp, _)| *fp == fingerprint) {
            entry.push((fingerprint, now));
            if entry.len() > inner.max_fingerprints_per_name {
                entry.remove(0);
            }
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<Arc<Vec<u8>>> {
        let inner = &self.inner;

        let cache = inner.cache.get(key);
        if let Some(cached) = cache {
            let age = cached.cached_at.elapsed();
            if age < cached.ttl {
                tracing::debug!("Cache hit for {}", key.qname);
                inner.metrics.hits.fetch_add(1, Ordering::Relaxed);
                if let Some(ref dm) = inner.dns_metrics {
                    dm.record_cache_hit();
                }
                return Some(cached.data.clone());
            } else if inner.serve_stale_enabled && age < cached.ttl + inner.serve_stale_max_stale {
                let stale_count = inner.stale_served_count.load(Ordering::Relaxed);
                if stale_count >= inner.max_stale_count {
                    tracing::debug!(
                        "Cache stale hit for {} rejected: stale_served_count {} >= max_stale_count {}",
                        key.qname, stale_count, inner.max_stale_count
                    );
                } else {
                    inner.stale_served_count.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("Cache stale hit for {} (age: {:?})", key.qname, age);
                    inner.metrics.stale_hits.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref dm) = inner.dns_metrics {
                        dm.record_cache_stale_hit();
                    }
                    return Some(cached.data.clone());
                }
            } else {
                tracing::debug!("Cache expired for {}", key.qname);
                inner.cache.invalidate(key);
                if let Some(keys) = inner.qname_index.write().get_mut(&key.qname) {
                    keys.remove(key);
                }
            }
        }

        inner.metrics.misses.fetch_add(1, Ordering::Relaxed);
        if let Some(ref dm) = inner.dns_metrics {
            dm.record_cache_miss();
        }
        None
    }

    pub fn get_with_metadata(&self, key: &CacheKey) -> Option<(Arc<Vec<u8>>, bool)> {
        let inner = &self.inner;

        let cache = inner.cache.get(key);
        if let Some(cached) = cache {
            let age = cached.cached_at.elapsed();
            if age < cached.ttl {
                tracing::debug!("Cache hit for {}", key.qname);
                inner.metrics.hits.fetch_add(1, Ordering::Relaxed);
                if let Some(ref dm) = inner.dns_metrics {
                    dm.record_cache_hit();
                }
                return Some((cached.data.clone(), false));
            } else if inner.serve_stale_enabled && age < cached.ttl + inner.serve_stale_max_stale {
                let stale_count = inner.stale_served_count.load(Ordering::Relaxed);
                if stale_count >= inner.max_stale_count {
                    tracing::debug!(
                        "Cache stale hit for {} rejected: stale_served_count {} >= max_stale_count {}",
                        key.qname, stale_count, inner.max_stale_count
                    );
                } else {
                    inner.stale_served_count.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("Cache stale hit for {} (age: {:?})", key.qname, age);
                    inner.metrics.stale_hits.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref dm) = inner.dns_metrics {
                        dm.record_cache_stale_hit();
                    }
                    return Some((cached.data.clone(), true));
                }
            } else {
                tracing::debug!("Cache expired for {}", key.qname);
                inner.cache.invalidate(key);
                if let Some(keys) = inner.qname_index.write().get_mut(&key.qname) {
                    keys.remove(key);
                }
            }
        }

        inner.metrics.misses.fetch_add(1, Ordering::Relaxed);
        if let Some(ref dm) = inner.dns_metrics {
            dm.record_cache_miss();
        }
        None
    }

    pub fn is_serve_stale_enabled(&self) -> bool {
        self.inner.serve_stale_enabled
    }

    pub fn insert(&self, key: CacheKey, data: Vec<u8>, record_ttl: u32) {
        let inner = &self.inner;

        if let Err(e) = self.validate_response(&key, &data) {
            tracing::warn!("Cache insert rejected: {}", e);
            return;
        }

        if inner.enable_fingerprinting {
            self.record_fingerprint(&key, &data);
        }

        let ttl_secs = record_ttl as u64;
        let ttl = Duration::from_secs(
            ttl_secs
                .min(inner.max_ttl.as_secs())
                .max(inner.min_ttl.as_secs()),
        );

        if ttl.as_secs() == 0 {
            return;
        }

        let fingerprint = Self::compute_fingerprint(&data);
        let cached = CachedResponse {
            data: Arc::new(data),
            ttl,
            cached_at: Instant::now(),
            fingerprint,
            source_ip: None,
            is_dnssec_signed: false,
        };

        inner.metrics.insertions.fetch_add(1, Ordering::Relaxed);
        if let Some(ref dm) = inner.dns_metrics {
            dm.record_cache_insertion();
        }
        inner.cache.insert(key.clone(), cached);

        // WS5: Reset stale served count on fresh insertion — fresh data means stale budget resets.
        inner.stale_served_count.store(0, Ordering::Relaxed);

        let mut index = inner.qname_index.write();
        index.entry(key.qname.clone()).or_default().insert(key);

        // Opportunistic cleanup: if index has significantly more entries than cache,
        // clean up stale entries caused by eviction
        if index.len() > inner.max_capacity * 2 {
            let stale_qnames: Vec<String> = index
                .iter()
                .filter(|(_, keys)| keys.is_empty())
                .map(|(qname, _)| qname.clone())
                .collect();
            for qname in stale_qnames {
                index.remove(&qname);
            }
        }
    }

    pub fn invalidate_zone(&self, origin: &str, reason: InvalidationReason) {
        let inner = &self.inner;

        // Use secondary index for O(1) qname lookup instead of linear scan
        let keys_to_remove: Vec<CacheKey> = {
            let index = inner.qname_index.read();
            index
                .iter()
                .filter(|(qname, _)| qname.ends_with(origin) || **qname == origin)
                .flat_map(|(_, keys)| keys.iter().cloned())
                .collect()
        };

        for key in keys_to_remove.iter() {
            inner.cache.invalidate(key);
        }

        // Opportunistic: also prune stale keys from the entire index
        // (keys that were evicted but we never cleaned up)
        {
            let mut index = inner.qname_index.write();
            index.retain(|qname, _| !qname.ends_with(origin) && *qname != origin);
            // Remove keys that no longer exist in cache
            let stale_qnames: Vec<String> = index
                .iter_mut()
                .map(|(qname, keys)| {
                    let before = keys.len();
                    keys.retain(|k| inner.cache.contains_key(k));
                    (qname.clone(), before != keys.len())
                })
                .filter(|(_, pruned)| *pruned)
                .map(|(qname, _)| qname)
                .collect();
            for qname in stale_qnames {
                if index.get(&qname).is_none_or(|k| k.is_empty()) {
                    index.remove(&qname);
                }
            }
        }

        // WS6: Clean up fingerprints keyed by the new composite format
        let origin_with_suffix = format!("{}|", origin);
        let mut fingerprints = inner.cache_fingerprints.write();
        fingerprints.retain(|name, _| !name.starts_with(&origin_with_suffix) && *name != origin);

        if !keys_to_remove.is_empty() {
            inner.metrics.invalidations.fetch_add(1, Ordering::Relaxed);
            Self::record_invalidation_reason(&inner.metrics, reason);
            if let Some(ref dm) = inner.dns_metrics {
                dm.record_cache_invalidation();
            }
            tracing::info!(
                "Invalidated {} cache entries for zone {} (reason: {})",
                keys_to_remove.len(),
                origin,
                reason
            );
        }
    }

    pub fn invalidate_record(
        &self,
        origin: &str,
        name: &str,
        record_type: RecordType,
        reason: InvalidationReason,
    ) {
        let inner = &self.inner;

        let full_name = if name == "@" || name.is_empty() {
            origin.to_string()
        } else {
            format!("{}.{}", name, origin)
        };

        let qtype_val: u16 = record_type.into();

        // Invalidate ALL transport-class/DNSSEC/ECS variants for this record.
        // The qname index stores keys grouped by qname; iterate and remove
        // all keys matching the record type regardless of other dimensions.
        let keys_to_remove: Vec<CacheKey> = {
            let index = inner.qname_index.read();
            index
                .get(&full_name)
                .map(|keys| {
                    keys.iter()
                        .filter(|k| k.qtype == qtype_val)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };

        for key in &keys_to_remove {
            inner.cache.invalidate(key);
            let fp_key = Self::fingerprint_key(key);
            inner.cache_fingerprints.write().remove(&fp_key);
        }

        // Remove matching keys from the index
        {
            let mut index = inner.qname_index.write();
            if let Some(keys) = index.get_mut(&full_name) {
                keys.retain(|k| k.qtype != qtype_val);
                if keys.is_empty() {
                    index.remove(&full_name);
                }
            }
        }

        if !keys_to_remove.is_empty() {
            inner.metrics.invalidations.fetch_add(1, Ordering::Relaxed);
            Self::record_invalidation_reason(&inner.metrics, reason);
            if let Some(ref dm) = inner.dns_metrics {
                dm.record_cache_invalidation();
            }
        }
        tracing::debug!(
            "Invalidated {} cache entries for {}/{:?} (reason: {})",
            keys_to_remove.len(),
            full_name,
            record_type,
            reason
        );
    }

    pub fn clear(&self, reason: InvalidationReason) {
        let inner = &self.inner;
        inner.cache.invalidate_all();

        let mut index = inner.qname_index.write();
        index.clear();

        let mut fingerprints = inner.cache_fingerprints.write();
        fingerprints.clear();

        inner.metrics.invalidations.fetch_add(1, Ordering::Relaxed);
        Self::record_invalidation_reason(&inner.metrics, reason);
        if let Some(ref dm) = inner.dns_metrics {
            dm.record_cache_invalidation();
        }

        tracing::info!("DNS cache cleared (reason: {})", reason);
    }

    /// Record a per-reason invalidation counter.
    fn record_invalidation_reason(metrics: &CacheMetrics, reason: InvalidationReason) {
        let label = reason.as_label().to_string();
        let mut map = metrics.invalidations_by_reason.write();
        map.entry(label)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn cleanup_fingerprints(&self, max_entries: usize) -> usize {
        let inner = &self.inner;
        let mut fingerprints = inner.cache_fingerprints.write();

        if fingerprints.len() <= max_entries {
            return 0;
        }

        let to_remove = fingerprints.len() - max_entries;
        let keys: Vec<String> = fingerprints.keys().take(to_remove).cloned().collect();

        for key in keys {
            fingerprints.remove(&key);
        }

        tracing::debug!("Cleaned up {} fingerprint entries", to_remove);
        to_remove
    }

    pub fn len(&self) -> usize {
        self.inner.cache.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn run_pending_tasks(&self) {
        self.inner.cache.run_pending_tasks();
    }

    pub fn stats(&self) -> CacheStats {
        let inner = &self.inner;
        let fingerprints = inner.cache_fingerprints.read();

        CacheStats {
            entries: inner.cache.iter().count(),
            fingerprints_tracked: fingerprints.len(),
            max_entries: inner.max_capacity,
            enable_source_validation: inner.enable_source_validation,
            enable_fingerprinting: inner.enable_fingerprinting,
        }
    }

    /// Return a snapshot of cache metrics.
    pub fn metrics(&self) -> CacheMetricsSnapshot {
        let m = &self.inner.metrics;
        let reason_snapshot = {
            let map = m.invalidations_by_reason.read();
            map.iter()
                .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
                .collect()
        };
        CacheMetricsSnapshot {
            hits: m.hits.load(Ordering::Relaxed),
            stale_hits: m.stale_hits.load(Ordering::Relaxed),
            negative_hits: m.negative_hits.load(Ordering::Relaxed),
            misses: m.misses.load(Ordering::Relaxed),
            insertions: m.insertions.load(Ordering::Relaxed),
            invalidations: m.invalidations.load(Ordering::Relaxed),
            poisoned_rejections: m.poisoned_rejections.load(Ordering::Relaxed),
            size_rejections: m.size_rejections.load(Ordering::Relaxed),
            invalidations_by_reason: reason_snapshot,
        }
    }
}

/// Snapshot of cache metrics with plain values (no atomics).
#[derive(Debug, Clone, Default)]
pub struct CacheMetricsSnapshot {
    pub hits: u64,
    pub stale_hits: u64,
    pub negative_hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub invalidations: u64,
    pub poisoned_rejections: u64,
    pub size_rejections: u64,
    /// Per-reason invalidation counts.
    pub invalidations_by_reason: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub enum CachePoisoningError {
    EntryTooLarge {
        size: usize,
        max: usize,
    },
    FingerprintMismatch {
        qname: String,
        expected: Vec<u64>,
        actual: u64,
    },
    PotentialPoisoning {
        qname: String,
        new_fingerprint: u64,
    },
    SourceMismatch {
        expected: IpAddr,
        actual: IpAddr,
    },
    InvalidSignature,
}

impl std::fmt::Display for CachePoisoningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntryTooLarge { size, max } => {
                write!(f, "Cache entry too large: {} bytes (max: {})", size, max)
            }
            Self::FingerprintMismatch {
                qname,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Fingerprint mismatch for {}: expected one of {:?}, got {}",
                    qname, expected, actual
                )
            }
            Self::PotentialPoisoning {
                qname,
                new_fingerprint,
            } => {
                write!(
                    f,
                    "Potential cache poisoning detected for {}: fingerprint {}",
                    qname, new_fingerprint
                )
            }
            Self::SourceMismatch { expected, actual } => {
                write!(
                    f,
                    "Source IP mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidSignature => {
                write!(f, "Invalid DNSSEC signature")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub fingerprints_tracked: usize,
    pub max_entries: usize,
    pub enable_source_validation: bool,
    pub enable_fingerprinting: bool,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(10000, 3600, 60)
    }
}

#[derive(Clone)]
pub struct SecureDnsCache(DnsCache);

impl SecureDnsCache {
    pub fn new(
        capacity: usize,
        max_ttl_secs: u64,
        min_ttl_secs: u64,
        max_entry_size: usize,
        enable_source_validation: bool,
        enable_fingerprinting: bool,
    ) -> Self {
        Self(DnsCache::with_security(
            capacity,
            max_ttl_secs,
            min_ttl_secs,
            max_entry_size,
            enable_source_validation,
            enable_fingerprinting,
        ))
    }

    pub fn get(&self, key: &CacheKey) -> Option<Arc<Vec<u8>>> {
        self.0.get(key)
    }

    pub fn insert(&self, key: CacheKey, data: Vec<u8>, record_ttl: u32) {
        self.0.insert(key, data, record_ttl);
    }

    pub fn invalidate_zone(&self, origin: &str, reason: InvalidationReason) {
        self.0.invalidate_zone(origin, reason);
    }

    pub fn invalidate_record(
        &self,
        origin: &str,
        name: &str,
        record_type: super::server::RecordType,
        reason: InvalidationReason,
    ) {
        self.0.invalidate_record(origin, name, record_type, reason);
    }

    pub fn clear(&self, reason: InvalidationReason) {
        self.0.clear(reason);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> CacheStats {
        self.0.stats()
    }

    pub fn metrics(&self) -> CacheMetricsSnapshot {
        self.0.metrics()
    }

    /// Attach `DnsMetrics` to bridge internal cache counters to Prometheus-exported metrics.
    pub fn with_metrics(self, metrics: Arc<DnsMetrics>) -> Self {
        Self(self.0.with_metrics(metrics))
    }
}

impl Default for SecureDnsCache {
    fn default() -> Self {
        Self::new(10000, 3600, 60, 65535, true, true)
    }
}

/// Compression-aware DNS name skipper. Used by `detect_dnssec_signed`.
/// Currently only reachable from the orphaned `sharded_cache.rs` module;
/// retained for when that module is integrated.
#[allow(dead_code)]
fn skip_name(data: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= data.len() {
            return None;
        }
        let octet = data[offset];
        if octet == 0 {
            return Some(offset + 1);
        }
        if octet >= 192 {
            if offset + 1 >= data.len() {
                return None;
            }
            return Some(offset + 2);
        } else {
            offset += 1 + octet as usize;
        }
    }
}

/// Detect whether a DNS response wire-format contains RRSIG records.
/// Used by `sharded_cache.rs` (currently orphaned) and tests.
#[allow(dead_code)]
pub(crate) fn detect_dnssec_signed(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    let mut offset = 12;
    for _ in 0..qdcount {
        if let Some(pos) = data[offset..].iter().position(|&b| b == 0) {
            offset += pos + 5;
            if offset > data.len() {
                return false;
            }
        } else {
            return false;
        }
    }

    for _ in 0..ancount {
        if let Some(name_end) = skip_name(data, offset) {
            offset = name_end;
            if offset + 10 > data.len() {
                return false;
            }
            let record_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            if record_type == 46 {
                return true;
            }
            offset += 8;
            let rdlen = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + rdlen;
            if offset > data.len() {
                return false;
            }
        } else {
            return false;
        }
    }

    false
}

#[cfg(test)]
mod phase7_cache_tests {
    use super::*;

    #[test]
    fn test_cache_key_dimensions_produce_distinct_keys() {
        let base = CacheKey::new("example.com".into(), RecordType::A, None);
        let different_qtype = CacheKey::new("example.com".into(), RecordType::AAAA, None);
        let different_class = CacheKey::with_class("example.com".into(), RecordType::A, 3, None);
        let different_dnssec = CacheKey::with_dnssec("example.com".into(), RecordType::A, None);
        let different_transport = CacheKey::with_transport(
            "example.com".into(),
            RecordType::A,
            None,
            TransportClass::Tcp,
        );
        let different_ns = CacheKey::recursive("example.com".into(), RecordType::A, None);
        let different_ecs = CacheKey::new(
            "example.com".into(),
            RecordType::A,
            Some("8.8.8.8".parse().unwrap()),
        );

        assert_ne!(base, different_qtype);
        assert_ne!(base, different_class);
        assert_ne!(base, different_dnssec);
        assert_ne!(base, different_transport);
        assert_ne!(base, different_ns);
        assert_ne!(base, different_ecs);
    }

    #[test]
    fn test_cache_key_canonicalize() {
        let mut key = CacheKey::new("Example.COM".into(), RecordType::A, None);
        key.canonicalize();
        assert_eq!(key.qname, "example.com");
    }

    #[test]
    fn test_ttl_clamping() {
        let cache = DnsCache::new(100, 300, 0);

        let key = CacheKey::new("ttl-test.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 0);
        assert!(
            cache.get(&key).is_none(),
            "TTL 0 with min_ttl=0 should not be cached"
        );

        let cache2 = DnsCache::new(100, 300, 10);
        cache2.insert(key.clone(), vec![1, 2, 3, 4], 5);
        let entry = cache2.inner.cache.get(&key).unwrap();
        assert_eq!(
            entry.ttl,
            Duration::from_secs(10),
            "Should clamp to min_ttl"
        );

        cache2.insert(key.clone(), vec![1, 2, 3, 4], 99999);
        let entry = cache2.inner.cache.get(&key).unwrap();
        assert_eq!(
            entry.ttl,
            Duration::from_secs(300),
            "Should clamp to max_ttl"
        );
    }

    #[test]
    fn test_fingerprint_composite_key_separates_types() {
        let cache = DnsCache::with_security(100, 300, 10, 65535, false, true);

        let a_key = CacheKey::new("fp-test.example.com".into(), RecordType::A, None);
        let aaaa_key = CacheKey::new("fp-test.example.com".into(), RecordType::AAAA, None);

        let a_data = vec![1, 2, 3, 4];
        let aaaa_data = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        cache.insert(a_key.clone(), a_data, 300);
        cache.insert(aaaa_key.clone(), aaaa_data, 300);

        assert!(cache.get(&a_key).is_some());
        assert!(cache.get(&aaaa_key).is_some());
    }

    #[test]
    fn test_fingerprint_key_format() {
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: true,
            client_subnet: None,
            transport_class: TransportClass::Udp512,
            namespace: CacheNamespace::Authoritative,
        };
        let fp_key = DnsCache::fingerprint_key(&key);
        assert_eq!(fp_key, "example.com|1|1|true|Authoritative");
    }

    #[test]
    fn test_serve_stale_max_stale_count() {
        // max_ttl_secs=300 so moka doesn't evict; min_ttl=1 so record_ttl=1 stays at 1
        let cache = DnsCache::with_serve_stale(100, 300, 1, true, 3600, 100);

        let key = CacheKey::new("stale-max.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 1);

        std::thread::sleep(Duration::from_millis(1100));

        assert!(cache.get(&key).is_some(), "First stale hit should work");
        assert!(cache.get(&key).is_some(), "Second stale hit should work");

        let metrics = cache.metrics();
        assert!(metrics.stale_hits >= 2, "Should track stale hits");
    }

    #[test]
    fn test_serve_stale_fresh_insert_resets_counter() {
        let cache = DnsCache::with_serve_stale(100, 300, 1, true, 3600, 100);

        let key1 = CacheKey::new("reset-test-1.example.com".into(), RecordType::A, None);
        let key2 = CacheKey::new("reset-test-2.example.com".into(), RecordType::A, None);

        cache.insert(key1.clone(), vec![1, 2, 3, 4], 1);
        std::thread::sleep(Duration::from_millis(1100));
        cache.get(&key1);

        cache.insert(key2.clone(), vec![5, 6, 7, 8], 300);
        assert!(cache.get(&key2).is_some(), "Fresh entry should be a hit");
    }

    #[test]
    fn test_metrics_tracking() {
        let cache = DnsCache::new(100, 300, 10);

        let key = CacheKey::new("metrics.example.com".into(), RecordType::A, None);
        cache.get(&key);
        assert_eq!(cache.metrics().misses, 1);

        cache.insert(key.clone(), vec![1, 2, 3, 4], 300);
        assert_eq!(cache.metrics().insertions, 1);

        cache.get(&key);
        assert_eq!(cache.metrics().hits, 1);

        cache.invalidate_zone("metrics.example.com", InvalidationReason::ZoneLoad);
        assert_eq!(cache.metrics().invalidations, 1);
    }

    #[test]
    fn test_zone_invalidation() {
        let cache = DnsCache::new(100, 300, 10);

        let key1 = CacheKey::new("a.zone-test.example.com".into(), RecordType::A, None);
        let key2 = CacheKey::new("b.zone-test.example.com".into(), RecordType::A, None);
        let key3 = CacheKey::new("other.example.com".into(), RecordType::A, None);

        cache.insert(key1.clone(), vec![1, 2, 3, 4], 300);
        cache.insert(key2.clone(), vec![5, 6, 7, 8], 300);
        cache.insert(key3.clone(), vec![9, 10, 11, 12], 300);

        cache.invalidate_zone("zone-test.example.com", InvalidationReason::ZoneDelete);

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_none());
        assert!(cache.get(&key3).is_some(), "Different zone should survive");
    }

    #[test]
    fn test_record_invalidation() {
        let cache = DnsCache::new(100, 300, 10);

        let key_a = CacheKey::new("rec-inv.example.com".into(), RecordType::A, None);
        let key_aaaa = CacheKey::new("rec-inv.example.com".into(), RecordType::AAAA, None);

        cache.insert(key_a.clone(), vec![1, 2, 3, 4], 300);
        cache.insert(
            key_aaaa.clone(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            300,
        );

        cache.invalidate_record(
            "example.com",
            "rec-inv",
            RecordType::A,
            InvalidationReason::RecordAdd,
        );

        assert!(
            cache.get(&key_a).is_none(),
            "A record should be invalidated"
        );
        assert!(cache.get(&key_aaaa).is_some(), "AAAA record should survive");
    }

    #[test]
    fn test_size_rejection() {
        let cache = DnsCache::with_security(100, 300, 10, 100, false, false);

        let key = CacheKey::new("size-reject.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![0u8; 200], 300);

        assert!(cache.get(&key).is_none());
        assert_eq!(cache.metrics().size_rejections, 1);
    }

    #[test]
    fn test_get_with_metadata_returns_stale_flag() {
        // max_ttl_secs=300 so moka doesn't evict; min_ttl=1 so record_ttl=1 stays at 1
        let cache = DnsCache::with_serve_stale(100, 300, 1, true, 3600, 100);

        let key = CacheKey::new("meta-test.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 1);

        let result = cache.get_with_metadata(&key);
        assert!(result.is_some());
        let (_, is_stale) = result.unwrap();
        assert!(!is_stale);

        std::thread::sleep(Duration::from_millis(1100));

        let result = cache.get_with_metadata(&key);
        assert!(result.is_some());
        let (_, is_stale) = result.unwrap();
        assert!(is_stale);
    }

    #[test]
    fn test_namespace_separation() {
        let cache = DnsCache::new(100, 300, 10);

        let auth_key = CacheKey::new("ns-test.example.com".into(), RecordType::A, None);
        let rec_key = CacheKey::recursive("ns-test.example.com".into(), RecordType::A, None);

        cache.insert(auth_key.clone(), vec![1, 2, 3, 4], 300);
        cache.insert(rec_key.clone(), vec![5, 6, 7, 8], 300);

        let auth_data = cache.get(&auth_key).unwrap();
        let rec_data = cache.get(&rec_key).unwrap();
        assert_ne!(*auth_data, *rec_data);
    }

    #[test]
    fn test_clear_all() {
        let cache = DnsCache::new(100, 300, 10);

        for i in 0..10 {
            let key = CacheKey::new(format!("clear-{}.example.com", i), RecordType::A, None);
            cache.insert(key, vec![1, 2, 3, 4], 300);
        }

        assert_eq!(cache.len(), 10);
        cache.clear(InvalidationReason::ManualFlush);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_metrics_snapshot_independence() {
        let cache = DnsCache::new(100, 300, 10);
        let key = CacheKey::new("snap.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 300);
        let snap1 = cache.metrics();
        cache.get(&key);
        let snap2 = cache.metrics();
        assert_eq!(snap1.hits, 0);
        assert_eq!(snap2.hits, 1);
    }

    #[test]
    fn test_cache_key_do_bit_separation() {
        let no_dnssec = CacheKey::new("example.com".into(), RecordType::A, None);
        let with_dnssec = CacheKey::with_dnssec("example.com".into(), RecordType::A, None);
        assert_ne!(no_dnssec, with_dnssec);
    }

    #[test]
    fn test_cache_key_transport_class_separation() {
        let udp = CacheKey::with_transport(
            "example.com".into(),
            RecordType::A,
            None,
            TransportClass::Udp512,
        );
        let tcp = CacheKey::with_transport(
            "example.com".into(),
            RecordType::A,
            None,
            TransportClass::Tcp,
        );
        let https = CacheKey::with_transport(
            "example.com".into(),
            RecordType::A,
            None,
            TransportClass::Http,
        );
        assert_ne!(udp, tcp);
        assert_ne!(udp, https);
        assert_ne!(tcp, https);
    }

    #[test]
    fn test_cache_key_client_subnet_separation() {
        let no_ecs = CacheKey::new("example.com".into(), RecordType::A, None);
        let ecs_1 = CacheKey::new(
            "example.com".into(),
            RecordType::A,
            Some("8.8.8.8".parse().unwrap()),
        );
        let ecs_2 = CacheKey::new(
            "example.com".into(),
            RecordType::A,
            Some("1.1.1.1".parse().unwrap()),
        );
        assert_ne!(no_ecs, ecs_1);
        assert_ne!(no_ecs, ecs_2);
        assert_ne!(ecs_1, ecs_2);
    }

    #[test]
    fn test_ttl_clamping_min_max() {
        let cache = DnsCache::new(100, 300, 60);

        let key_below_min = CacheKey::new("ttl-clamp-min.example.com".into(), RecordType::A, None);
        cache.insert(key_below_min.clone(), vec![1, 2, 3, 4], 5);
        let entry = cache.inner.cache.get(&key_below_min).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(60));

        let key_above_max = CacheKey::new("ttl-clamp-max.example.com".into(), RecordType::A, None);
        cache.insert(key_above_max.clone(), vec![1, 2, 3, 4], 99999);
        let entry = cache.inner.cache.get(&key_above_max).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(300));

        let key_in_range = CacheKey::new("ttl-clamp-range.example.com".into(), RecordType::A, None);
        cache.insert(key_in_range.clone(), vec![1, 2, 3, 4], 120);
        let entry = cache.inner.cache.get(&key_in_range).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(120));
    }

    #[test]
    fn test_negative_ttl_from_config() {
        let cache = DnsCache::new(100, 300, 30);

        let key = CacheKey::new("neg-ttl.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 0);
        let entry = cache.inner.cache.get(&key).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(30));

        let key2 = CacheKey::new("neg-ttl2.example.com".into(), RecordType::A, None);
        cache.insert(key2.clone(), vec![1, 2, 3, 4], 10);
        let entry = cache.inner.cache.get(&key2).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(30));
    }

    #[test]
    fn test_zone_invalidation_clears_all_variants() {
        let cache = DnsCache::with_security(100, 300, 10, 65535, false, false);

        let key_auth = CacheKey::new("sub.variant.example.com".into(), RecordType::A, None);
        let key_dnssec =
            CacheKey::with_dnssec("sub.variant.example.com".into(), RecordType::A, None);
        let key_ecs = CacheKey::new(
            "sub.variant.example.com".into(),
            RecordType::A,
            Some("8.8.8.8".parse().unwrap()),
        );
        let key_tcp = CacheKey::with_transport(
            "sub.variant.example.com".into(),
            RecordType::A,
            None,
            TransportClass::Tcp,
        );

        cache.insert(key_auth.clone(), vec![1, 2, 3, 4], 300);
        cache.insert(key_dnssec.clone(), vec![5, 6, 7, 8], 300);
        cache.insert(key_ecs.clone(), vec![9, 10, 11, 12], 300);
        cache.insert(key_tcp.clone(), vec![13, 14, 15, 16], 300);

        assert_eq!(cache.len(), 4);
        cache.invalidate_zone("variant.example.com", InvalidationReason::ZoneDelete);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_record_invalidation_specific_type() {
        let cache = DnsCache::new(100, 300, 10);

        let key_a = CacheKey::new("typed.inv.example.com".into(), RecordType::A, None);
        let key_aaaa = CacheKey::new("typed.inv.example.com".into(), RecordType::AAAA, None);
        let key_mx = CacheKey::new("typed.inv.example.com".into(), RecordType::MX, None);

        cache.insert(key_a.clone(), vec![1, 2, 3, 4], 300);
        cache.insert(
            key_aaaa.clone(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            300,
        );
        cache.insert(
            key_mx.clone(),
            vec![0, 10, 0, 0, 5, 6, 7, 8, 10, 11, 12, 13],
            300,
        );

        cache.invalidate_record(
            "example.com",
            "typed.inv",
            RecordType::A,
            InvalidationReason::RecordAdd,
        );

        assert!(cache.get(&key_a).is_none());
        assert!(cache.get(&key_aaaa).is_some());
        assert!(cache.get(&key_mx).is_some());
    }

    #[test]
    fn test_invalidation_removes_negative_entries() {
        let cache = DnsCache::with_security(100, 300, 10, 65535, false, false);

        let key = CacheKey::new("neg-inv.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![], 0);
        assert!(
            cache.get(&key).is_some(),
            "Negative entry should be cached with min_ttl"
        );

        cache.insert(key.clone(), vec![1, 2, 3, 4], 300);
        let data = cache.get(&key).unwrap();
        assert_eq!(
            *data,
            vec![1, 2, 3, 4],
            "Positive entry should replace negative"
        );
    }

    #[test]
    fn test_serve_stale_disabled_returns_miss() {
        let cache = DnsCache::with_serve_stale(100, 300, 1, false, 3600, 100);

        let key = CacheKey::new("stale-disabled.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 1);

        assert!(cache.get(&key).is_some(), "Fresh entry should hit");

        std::thread::sleep(Duration::from_millis(1100));

        assert!(
            cache.get(&key).is_none(),
            "Stale entry should miss when serve_stale disabled"
        );
    }

    #[test]
    fn test_serve_stale_beyond_max_window_returns_miss() {
        let cache = DnsCache::with_serve_stale(100, 300, 1, true, 2, 100);

        let key = CacheKey::new("stale-window.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 1);

        assert!(cache.get(&key).is_some(), "Fresh entry should hit");

        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            cache.get(&key).is_some(),
            "Within max_stale window should hit"
        );

        std::thread::sleep(Duration::from_millis(2000));
        assert!(
            cache.get(&key).is_none(),
            "Beyond max_stale window should miss"
        );
    }

    #[test]
    fn test_zone_update_invalidates_stale_entry() {
        let cache = DnsCache::with_serve_stale(100, 300, 1, true, 3600, 100);

        let key = CacheKey::new("stale-zone-inv.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 1);

        std::thread::sleep(Duration::from_millis(1100));
        assert!(cache.get(&key).is_some(), "Stale entry should be served");

        cache.invalidate_zone("stale-zone-inv.example.com", InvalidationReason::ZoneDelete);
        assert!(
            cache.get(&key).is_none(),
            "After invalidation, stale entry should be gone"
        );
    }

    #[test]
    fn test_a_aaaa_no_fingerprint_conflict() {
        let cache = DnsCache::with_security(100, 300, 10, 65535, true, true);

        let a_key = CacheKey::new("fp-conflict.example.com".into(), RecordType::A, None);
        let aaaa_key = CacheKey::new("fp-conflict.example.com".into(), RecordType::AAAA, None);

        let a_data = vec![0, 0, 0, 0];
        let aaaa_data = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        cache.insert(a_key.clone(), a_data, 300);
        assert!(cache.get(&a_key).is_some(), "A record should be accepted");

        cache.insert(aaaa_key.clone(), aaaa_data, 300);
        assert!(
            cache.get(&aaaa_key).is_some(),
            "AAAA record should be accepted without poisoning rejection"
        );

        assert_eq!(cache.metrics().poisoned_rejections, 0);
    }

    #[test]
    fn test_dnssec_nondnssec_no_conflict() {
        let cache = DnsCache::with_security(100, 300, 10, 65535, true, true);

        let nondnssec_key =
            CacheKey::new("dnssec-conflict.example.com".into(), RecordType::A, None);
        let dnssec_key =
            CacheKey::with_dnssec("dnssec-conflict.example.com".into(), RecordType::A, None);

        let data1 = vec![1, 2, 3, 4];
        let data2 = vec![5, 6, 7, 8];

        cache.insert(nondnssec_key.clone(), data1, 300);
        assert!(cache.get(&nondnssec_key).is_some());

        cache.insert(dnssec_key.clone(), data2, 300);
        assert!(cache.get(&dnssec_key).is_some());

        assert_eq!(cache.metrics().poisoned_rejections, 0);
    }

    #[test]
    fn test_metrics_stale_hit_counter() {
        let cache = DnsCache::with_serve_stale(100, 300, 1, true, 3600, 100);

        let key = CacheKey::new("stale-metrics.example.com".into(), RecordType::A, None);
        cache.insert(key.clone(), vec![1, 2, 3, 4], 1);

        assert_eq!(cache.metrics().stale_hits, 0);

        std::thread::sleep(Duration::from_millis(1100));

        cache.get(&key);
        assert_eq!(cache.metrics().stale_hits, 1);

        cache.get(&key);
        assert_eq!(cache.metrics().stale_hits, 2);
    }

    #[test]
    fn test_metrics_miss_counter() {
        let cache = DnsCache::new(100, 300, 10);

        let key = CacheKey::new("miss-metrics.example.com".into(), RecordType::A, None);

        assert_eq!(cache.metrics().misses, 0);

        cache.get(&key);
        assert_eq!(cache.metrics().misses, 1);

        cache.get(&key);
        assert_eq!(cache.metrics().misses, 2);
    }

    #[test]
    fn test_metrics_invalidation_counter() {
        let cache = DnsCache::new(100, 300, 10);

        let key1 = CacheKey::new("inv-metrics.example.com".into(), RecordType::A, None);
        let key2 = CacheKey::new("other.example.com".into(), RecordType::A, None);

        cache.insert(key1, vec![1, 2, 3, 4], 300);
        cache.insert(key2, vec![5, 6, 7, 8], 300);

        assert_eq!(cache.metrics().invalidations, 0);

        cache.invalidate_zone("inv-metrics.example.com", InvalidationReason::ZoneLoad);
        assert_eq!(cache.metrics().invalidations, 1);

        cache.invalidate_zone("other.example.com", InvalidationReason::ZoneLoad);
        assert_eq!(cache.metrics().invalidations, 2);
    }
}

#[cfg(test)]
mod dnssec_detection_tests {
    use super::*;

    #[test]
    fn test_detect_dnssec_signed_with_rrsig() {
        // ANCOUNT must be 2 for two records (A and RRSIG)!
        let data = vec![
            // Header: QDCOUNT=1, ANCOUNT=2
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // Question: root QNAME + QTYPE=A + QCLASS=IN
            0x00, 0x00, 0x01, 0x00, 0x01,
            // Answer A: root NAME + TYPE=A + CLASS + TTL + RDLENGTH + RDATA
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x22,
            // Answer RRSIG: root NAME + TYPE=RRSIG + CLASS + TTL + RDLENGTH + RDATA
            0x00, 0x00, 0x2E, 0x00, 0x01, 0x00, 0x00, 0x03, 0x84, 0x00, 0x17, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(detect_dnssec_signed(&data));
    }

    #[test]
    fn test_detect_dnssec_signed_without_rrsig() {
        let data = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x22,
        ];
        assert!(!detect_dnssec_signed(&data));
    }

    #[test]
    fn test_detect_dnssec_signed_empty_answer() {
        let data = vec![
            0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        assert!(!detect_dnssec_signed(&data));
    }

    #[test]
    fn test_detect_dnssec_signed_truncated_data() {
        assert!(!detect_dnssec_signed(&[]));
        assert!(!detect_dnssec_signed(&[0x00, 0x00, 0x00]));
        assert!(!detect_dnssec_signed(&[0x00; 11]));
        assert!(!detect_dnssec_signed(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00
        ]));
    }
}

#[cfg(test)]
mod invalidation_reason_tests {
    use super::*;

    #[test]
    fn test_invalidation_reason_all_labels() {
        assert_eq!(InvalidationReason::ZoneLoad.as_label(), "zone_load");
        assert_eq!(
            InvalidationReason::ZoneLoadFromStore.as_label(),
            "zone_load_from_store"
        );
        assert_eq!(InvalidationReason::RecordAdd.as_label(), "record_add");
        assert_eq!(InvalidationReason::ZoneDelete.as_label(), "zone_delete");
        assert_eq!(
            InvalidationReason::DynamicUpdate.as_label(),
            "dynamic_update"
        );
        assert_eq!(
            InvalidationReason::NotifyReceived.as_label(),
            "notify_received"
        );
        assert_eq!(InvalidationReason::ManualFlush.as_label(), "manual_flush");
        assert_eq!(
            InvalidationReason::DnssecKeyRollover.as_label(),
            "dnssec_key_rollover"
        );
        assert_eq!(
            InvalidationReason::RpzZoneRemoval.as_label(),
            "rpz_zone_removal"
        );
        assert_eq!(
            InvalidationReason::ZoneTransferAxfr.as_label(),
            "zone_transfer_axfr"
        );
        assert_eq!(
            InvalidationReason::ZoneTransferIxfr.as_label(),
            "zone_transfer_ixfr"
        );
    }

    #[test]
    fn test_invalidation_reason_display() {
        assert_eq!(format!("{}", InvalidationReason::ZoneLoad), "zone_load");
        assert_eq!(
            format!("{}", InvalidationReason::ZoneTransferAxfr),
            "zone_transfer_axfr"
        );
        assert_eq!(
            format!("{}", InvalidationReason::ZoneTransferIxfr),
            "zone_transfer_ixfr"
        );
    }

    #[test]
    fn test_cache_invalidate_zone_axfr() {
        let cache = DnsCache::new(1000, 300, 86400);
        let key = CacheKey::new("example.com".into(), RecordType::A, None);
        let response = vec![0u8; 12];
        cache.insert(key.clone(), response, 300);

        cache.invalidate_zone("example.com", InvalidationReason::ZoneTransferAxfr);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.metrics().invalidations, 1);
    }

    #[test]
    fn test_cache_invalidate_zone_ixfr() {
        let cache = DnsCache::new(1000, 300, 86400);
        let key = CacheKey::new("example.com".into(), RecordType::A, None);
        let response = vec![0u8; 12];
        cache.insert(key.clone(), response, 300);

        cache.invalidate_zone("example.com", InvalidationReason::ZoneTransferIxfr);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.metrics().invalidations, 1);
    }
}
