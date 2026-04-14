use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    pub enabled: bool,
    pub min_query_count: u32,
    pub prefetch_ttl_threshold: u32,
    pub max_prefetched_names: usize,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_query_count: 10,
            prefetch_ttl_threshold: 300,
            max_prefetched_names: 1000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryStats {
    pub query_count: u32,
    pub last_queried: Instant,
}

pub struct DnsPrefetcher {
    config: PrefetchConfig,
    query_stats: RwLock<HashMap<String, QueryStats>>,
    prefetched_signatures: RwLock<HashMap<String, PrefetchedSignature>>,
    cleanup_interval: Duration,
    last_cleanup: RwLock<Instant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct PrefetchedSignature {
    pub qname: String,
    pub qtype: u16,
    pub signed_data: Vec<u8>,
    pub expires_at: u64,
    pub created_at: u64,
}

impl DnsPrefetcher {
    pub fn new(config: PrefetchConfig) -> Self {
        Self {
            config,
            query_stats: RwLock::new(HashMap::new()),
            prefetched_signatures: RwLock::new(HashMap::new()),
            cleanup_interval: Duration::from_secs(300),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    pub fn record_query(&self, qname: &str, qtype: u16) {
        if !self.config.enabled {
            return;
        }

        let key = format!("{}:{}", qname.to_lowercase(), qtype);
        let mut stats = self.query_stats.write();

        if let Some(entry) = stats.get_mut(&key) {
            entry.query_count += 1;
            entry.last_queried = Instant::now();
        } else {
            stats.insert(
                key,
                QueryStats {
                    query_count: 1,
                    last_queried: Instant::now(),
                },
            );
        }
    }

    pub fn should_prefetch(&self, qname: &str, qtype: u16) -> bool {
        if !self.config.enabled {
            return false;
        }

        let key = format!("{}:{}", qname.to_lowercase(), qtype);
        let stats = self.query_stats.read();

        if let Some(entry) = stats.get(&key) {
            entry.query_count >= self.config.min_query_count
        } else {
            false
        }
    }

    pub fn store_prefetched(&self, qname: String, qtype: u16, signed_data: Vec<u8>, ttl: u32) {
        if !self.config.enabled {
            return;
        }

        let key = format!("{}:{}", qname.to_lowercase(), qtype);
        let now = crate::utils::safe_unix_timestamp();

        let expires_at = now + (ttl as u64);

        let mut signatures = self.prefetched_signatures.write();

        if signatures.len() >= self.config.max_prefetched_names {
            self.cleanup_stale(&mut signatures);
        }

        signatures.insert(
            key,
            PrefetchedSignature {
                qname: qname.clone(),
                qtype,
                signed_data,
                expires_at,
                created_at: now,
            },
        );
    }

    pub fn get_prefetched(&self, qname: &str, qtype: u16) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }

        let key = format!("{}:{}", qname.to_lowercase(), qtype);
        let signatures = self.prefetched_signatures.read();

        if let Some(sig) = signatures.get(&key) {
            let now = crate::utils::safe_unix_timestamp();

            if sig.expires_at > now {
                return Some(sig.signed_data.clone());
            }
        }

        None
    }

    fn cleanup_stale(&self, signatures: &mut HashMap<String, PrefetchedSignature>) {
        let now = crate::utils::safe_unix_timestamp();

        signatures.retain(|_, v| v.expires_at > now);

        while signatures.len() > self.config.max_prefetched_names {
            if let Some((key, _)) = signatures.iter().next().cloned() {
                signatures.remove(&key);
            }
        }
    }

    pub fn cleanup_if_needed(&self) {
        let now = Instant::now();
        let last = *self.last_cleanup.read();

        if now.duration_since(last) > self.cleanup_interval {
            let mut signatures = self.prefetched_signatures.write();
            self.cleanup_stale(&mut signatures);
            *self.last_cleanup.write() = now;
        }
    }

    pub fn get_stats(&self) -> PrefetchStats {
        let query_stats = self.query_stats.read();
        let signatures = self.prefetched_signatures.read();

        let hot_names: Vec<(String, u32)> = query_stats
            .iter()
            .filter(|(_, v)| v.query_count >= self.config.min_query_count)
            .map(|(k, v)| (k.clone(), v.query_count))
            .collect();

        PrefetchStats {
            total_tracked_names: query_stats.len(),
            prefetched_signatures: signatures.len(),
            hot_names,
        }
    }

    pub fn reset_stats(&self) {
        let mut stats = self.query_stats.write();
        stats.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct PrefetchStats {
    pub total_tracked_names: usize,
    pub prefetched_signatures: usize,
    pub hot_names: Vec<(String, u32)>,
}

pub struct DnsPrefetchManager {
    prefetcher: Arc<DnsPrefetcher>,
}

impl DnsPrefetchManager {
    pub fn new(config: PrefetchConfig) -> Self {
        Self {
            prefetcher: Arc::new(DnsPrefetcher::new(config)),
        }
    }

    pub fn get_prefetcher(&self) -> Arc<DnsPrefetcher> {
        self.prefetcher.clone()
    }
}

impl Default for DnsPrefetchManager {
    fn default() -> Self {
        Self::new(PrefetchConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefetch_disabled_by_default() {
        let config = PrefetchConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn test_record_query() {
        let prefetcher = DnsPrefetcher::new(PrefetchConfig {
            enabled: true,
            min_query_count: 5,
            prefetch_ttl_threshold: 300,
            max_prefetched_names: 100,
        });

        for _ in 0..5 {
            prefetcher.record_query("example.com", 1);
        }

        assert!(prefetcher.should_prefetch("example.com", 1));
        assert!(!prefetcher.should_prefetch("other.com", 1));
    }

    #[test]
    fn test_prefetched_signature_expiry() {
        let prefetcher = DnsPrefetcher::new(PrefetchConfig::default());

        prefetcher.store_prefetched("example.com".to_string(), 1, vec![1, 2, 3, 4], 3600);

        let result = prefetcher.get_prefetched("example.com", 1);
        assert!(result.is_some());
    }
}
