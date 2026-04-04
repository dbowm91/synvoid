use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHasher;
use moka::sync::Cache;
use parking_lot::RwLock;

use super::server::RecordType;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub client_subnet: Option<IpAddr>,
}

impl CacheKey {
    pub fn new(qname: String, qtype: RecordType, client_subnet: Option<IpAddr>) -> Self {
        Self {
            qname,
            qtype: qtype.into(),
            client_subnet,
        }
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
}

impl DnsCache {
    pub fn new(capacity: usize, max_ttl_secs: u64, min_ttl_secs: u64) -> Self {
        let cache = Cache::new(capacity as u64);

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
        let cache = Cache::new(capacity as u64);

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
            }),
        }
    }

    pub fn with_serve_stale(
        capacity: usize,
        max_ttl_secs: u64,
        min_ttl_secs: u64,
        serve_stale_enabled: bool,
        serve_stale_max_stale_secs: u64,
    ) -> Self {
        let cache = Cache::new(capacity as u64);

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
            }),
        }
    }

    pub fn compute_fingerprint(data: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = AHasher::default();
        data.hash(&mut hasher);
        hasher.finish()
    }

    fn validate_response(&self, key: &CacheKey, data: &[u8]) -> Result<(), CachePoisoningError> {
        let inner = &self.inner;

        if data.len() > inner.max_entry_size {
            return Err(CachePoisoningError::EntryTooLarge {
                size: data.len(),
                max: inner.max_entry_size,
            });
        }

        if inner.enable_fingerprinting {
            let fingerprint = Self::compute_fingerprint(data);
            let qname = key.qname.clone();
            let fingerprints = inner.cache_fingerprints.write();

            if let Some(existing) = fingerprints.get(&qname) {
                let has_fingerprint = existing.iter().any(|(fp, _)| *fp == fingerprint);
                if existing.len() >= inner.max_fingerprints_per_name {
                    if !has_fingerprint {
                        let fps: Vec<u64> = existing.iter().map(|(fp, _)| *fp).collect();
                        return Err(CachePoisoningError::FingerprintMismatch {
                            qname: qname.clone(),
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
                    if confirmations < 2 {
                        tracing::warn!(
                            "Potential cache poisoning attempt detected for {} (unconfirmed fingerprint: {})",
                            qname,
                            fingerprint
                        );
                    } else {
                        tracing::warn!(
                            "Potential cache poisoning attempt detected for {} (new fingerprint: {})",
                            qname,
                            fingerprint
                        );
                    }
                    return Err(CachePoisoningError::PotentialPoisoning {
                        qname: qname.clone(),
                        new_fingerprint: fingerprint,
                    });
                }
            }
        }

        Ok(())
    }

    fn record_fingerprint(&self, key: &CacheKey, data: &[u8]) {
        let inner = &self.inner;

        if !inner.enable_fingerprinting {
            return;
        }

        let fingerprint = Self::compute_fingerprint(data);
        let qname = key.qname.clone();
        let now = Instant::now();
        let mut fingerprints = inner.cache_fingerprints.write();

        let entry = fingerprints.entry(qname).or_default();

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
                return Some(cached.data.clone());
            } else if inner.serve_stale_enabled && age < cached.ttl + inner.serve_stale_max_stale {
                tracing::debug!("Cache stale hit for {} (age: {:?})", key.qname, age);
                return Some(cached.data.clone());
            } else {
                tracing::debug!("Cache expired for {}", key.qname);
                inner.cache.invalidate(key);
                if let Some(keys) = inner.qname_index.write().get_mut(&key.qname) {
                    keys.remove(key);
                }
            }
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
                return Some((cached.data.clone(), false));
            } else if inner.serve_stale_enabled && age < cached.ttl + inner.serve_stale_max_stale {
                tracing::debug!("Cache stale hit for {} (age: {:?})", key.qname, age);
                return Some((cached.data.clone(), true));
            } else {
                tracing::debug!("Cache expired for {}", key.qname);
                inner.cache.invalidate(key);
                if let Some(keys) = inner.qname_index.write().get_mut(&key.qname) {
                    keys.remove(key);
                }
            }
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

        inner.cache.insert(key.clone(), cached);

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

    pub fn invalidate_zone(&self, origin: &str) {
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

        let mut fingerprints = inner.cache_fingerprints.write();
        fingerprints.retain(|name, _| !name.ends_with(origin) && *name != origin);

        if !keys_to_remove.is_empty() {
            tracing::info!(
                "Invalidated {} cache entries for zone {}",
                keys_to_remove.len(),
                origin
            );
        }
    }

    pub fn invalidate_record(&self, origin: &str, name: &str, record_type: RecordType) {
        let inner = &self.inner;

        let full_name = if name == "@" || name.is_empty() {
            origin.to_string()
        } else {
            format!("{}.{}", name, origin)
        };

        let key = CacheKey::new(full_name, record_type, None);
        inner.cache.invalidate(&key);
        if let Some(keys) = inner.qname_index.write().get_mut(&key.qname) {
            keys.remove(&key);
        }

        tracing::debug!("Invalidated cache entry for {}/{:?}", key.qname, key.qtype);
    }

    pub fn clear(&self) {
        let inner = &self.inner;
        inner.cache.invalidate_all();

        let mut index = inner.qname_index.write();
        index.clear();

        let mut fingerprints = inner.cache_fingerprints.write();
        fingerprints.clear();

        tracing::info!("DNS cache cleared");
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
        self.inner.cache.entry_count() as usize
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
            entries: inner.cache.entry_count() as usize,
            fingerprints_tracked: fingerprints.len(),
            max_entries: inner.max_capacity,
            enable_source_validation: inner.enable_source_validation,
            enable_fingerprinting: inner.enable_fingerprinting,
        }
    }
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

    pub fn insert(
        &self,
        key: CacheKey,
        data: Vec<u8>,
        record_ttl: u32,
        _source_ip: Option<IpAddr>,
        _is_dnssec_signed: bool,
    ) {
        self.0.insert(key, data, record_ttl);
    }

    pub fn invalidate_zone(&self, origin: &str) {
        self.0.invalidate_zone(origin);
    }

    pub fn invalidate_record(
        &self,
        origin: &str,
        name: &str,
        record_type: super::server::RecordType,
    ) {
        self.0.invalidate_record(origin, name, record_type);
    }

    pub fn clear(&self) {
        self.0.clear();
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
}

impl Default for SecureDnsCache {
    fn default() -> Self {
        Self::new(10000, 3600, 60, 65535, true, true)
    }
}

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
