use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use moka::sync::Cache;
use parking_lot::RwLock;
use thiserror::Error;

use super::config::ProxyCacheSettings;
use super::key::CacheKey;

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cache disabled")]
    Disabled,
    #[error("Entry not found: {0}")]
    NotFound(String),
    #[error("Entry expired: {0}")]
    Expired(String),
    #[error("Response not cacheable")]
    NotCacheable,
}

#[derive(Clone)]
pub struct ProxyCacheEntry {
    pub content: Bytes,
    pub status: u16,
    pub headers: HeaderMap,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub expires_at: Option<Instant>,
    pub stale_while_revalidate: Option<Instant>,
    pub stale_if_error: Option<Instant>,
    pub content_length: Option<usize>,
    pub is_fresh: bool,
}

impl ProxyCacheEntry {
    pub fn new(
        content: Bytes,
        status: u16,
        headers: HeaderMap,
        max_age: Option<Duration>,
        swr: Option<Duration>,
        sie: Option<Duration>,
    ) -> Self {
        let now = Instant::now();
        let expires_at = max_age.map(|age| now + age);
        let stale_while_revalidate = swr.and_then(|d| expires_at.map(|e| e + d));
        let stale_if_error = sie.and_then(|d| expires_at.map(|e| e + d));

        Self {
            content,
            status,
            headers,
            created_at: now,
            last_accessed: now,
            expires_at,
            stale_while_revalidate,
            stale_if_error,
            content_length: None,
            is_fresh: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            return Instant::now() > expires_at;
        }
        false
    }

    pub fn is_stale(&self) -> bool {
        self.is_expired()
    }

    pub fn is_stale_while_revalidate(&self) -> bool {
        if let Some(swr) = self.stale_while_revalidate {
            return Instant::now() <= swr && self.is_expired();
        }
        false
    }

    pub fn is_stale_if_error(&self) -> bool {
        if let Some(sie) = self.stale_if_error {
            return Instant::now() <= sie && self.is_expired();
        }
        false
    }

    pub fn age(&self) -> Duration {
        self.last_accessed.duration_since(self.created_at)
    }

    pub fn update_access(&mut self) {
        self.last_accessed = Instant::now();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheHit {
    Hit,
    Miss,
    Expired,
    Stale,
    StaleWhileRevalidate,
}

#[derive(Clone)]
struct CacheEntryInner {
    entry: Arc<ProxyCacheEntry>,
    size: usize,
    on_disk: bool,
    disk_path: Option<PathBuf>,
    checksum: u64,
}

impl CacheEntryInner {
    fn compute_checksum(content: &[u8]) -> u64 {
        use ahash::AHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = AHasher::default();
        content.hash(&mut hasher);
        hasher.finish()
    }

    // SAFETY_REASON: Reserved for cache integrity verification
    #[allow(dead_code)]
    fn validate(&self, content: &[u8]) -> bool {
        Self::compute_checksum(content) == self.checksum
    }
}

pub struct ProxyCache {
    entries: Cache<CacheKey, CacheEntryInner>,
    settings: ProxyCacheSettings,
    disk_path: PathBuf,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    current_memory_size: AtomicU64,
    cleanup_shutdown_tx: Arc<tokio::sync::watch::Sender<()>>,
    host_index: RwLock<HashMap<String, Vec<CacheKey>>>,
}

impl Clone for ProxyCache {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            settings: self.settings.clone(),
            disk_path: self.disk_path.clone(),
            cache_hits: AtomicU64::new(self.cache_hits.load(Ordering::Relaxed)),
            cache_misses: AtomicU64::new(self.cache_misses.load(Ordering::Relaxed)),
            current_memory_size: AtomicU64::new(self.current_memory_size.load(Ordering::Relaxed)),
            cleanup_shutdown_tx: self.cleanup_shutdown_tx.clone(),
            host_index: RwLock::new(HashMap::new()),
        }
    }
}

impl ProxyCache {
    pub fn new(settings: ProxyCacheSettings) -> Self {
        let disk_path = settings.path.clone();
        let max_memory = settings.max_memory_size as u64;

        let cache: Cache<CacheKey, CacheEntryInner> = Cache::builder()
            .weigher(|_, v: &CacheEntryInner| -> u32 {
                if v.on_disk {
                    1 // Disk-backed entries have minimal memory footprint
                } else {
                    v.size.min(u32::MAX as usize) as u32
                }
            })
            .max_capacity(max_memory)
            .build();

        if settings.enabled && settings.path.exists() {
            if let Err(e) = std::fs::create_dir_all(&settings.path) {
                tracing::warn!("Failed to create cache directory: {}", e);
            }
        }

        let (shutdown_tx, _) = tokio::sync::watch::channel(());
        Self {
            entries: cache,
            settings,
            disk_path,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            current_memory_size: AtomicU64::new(0),
            cleanup_shutdown_tx: Arc::new(shutdown_tx),
            host_index: RwLock::new(HashMap::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    pub fn settings(&self) -> &ProxyCacheSettings {
        &self.settings
    }

    pub fn start_background_cleanup(&self, interval_secs: u64) -> tokio::task::JoinHandle<()> {
        let cache = Arc::new(self.clone());
        let mut shutdown_rx = self.cleanup_shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Cache cleanup: shutdown signal received");
                        break;
                    }
                    _ = interval.tick() => {
                        let removed = cache.cleanup_expired();
                        if removed > 0 {
                            tracing::debug!("Cache cleanup: removed {} expired entries", removed);
                        }
                    }
                }
            }
        })
    }

    pub fn shutdown(&self) {
        let _ = self.cleanup_shutdown_tx.send(());
    }

    #[inline]
    pub async fn get(&self, key: &CacheKey) -> Option<Arc<ProxyCacheEntry>> {
        if !self.settings.enabled {
            return None;
        }

        let inner = self.entries.get(key)?;

        if inner.on_disk {
            drop(inner);
            return self.get_async(key).await;
        }

        if inner.entry.is_expired() {
            if inner.entry.is_stale_while_revalidate() {
                let mut entry = (*inner.entry).clone();
                entry.is_fresh = false;
                entry.update_access();
                let updated_inner = CacheEntryInner {
                    entry: Arc::new(entry),
                    size: inner.size,
                    on_disk: inner.on_disk,
                    disk_path: inner.disk_path.clone(),
                    checksum: inner.checksum,
                };
                return Some(
                    self.entries
                        .entry(key.clone())
                        .or_insert(updated_inner)
                        .into_value()
                        .entry,
                );
            }
            if inner.entry.is_stale_if_error() {
                let mut entry = (*inner.entry).clone();
                entry.is_fresh = false;
                entry.update_access();
                let updated_inner = CacheEntryInner {
                    entry: Arc::new(entry),
                    size: inner.size,
                    on_disk: inner.on_disk,
                    disk_path: inner.disk_path.clone(),
                    checksum: inner.checksum,
                };
                return Some(
                    self.entries
                        .entry(key.clone())
                        .or_insert(updated_inner)
                        .into_value()
                        .entry,
                );
            }
            drop(inner);
            self.entries.invalidate(key);
            return None;
        }

        Some(inner.entry)
    }

    #[inline]
    async fn get_async(&self, key: &CacheKey) -> Option<Arc<ProxyCacheEntry>> {
        let inner = self.entries.get(key)?;

        let disk_path = inner.disk_path.clone()?;
        let checksum = inner.checksum;
        let entry = (*inner.entry).clone();
        drop(inner);

        let content = tokio::task::spawn_blocking(move || std::fs::read(&disk_path))
            .await
            .ok()
            .and_then(|r| r.ok())?;

        if checksum != CacheEntryInner::compute_checksum(&content) {
            tracing::warn!("Cache entry checksum mismatch, removing corrupted entry");
            self.invalidate(key);
            return None;
        }

        let mut entry = entry;
        entry.content = Bytes::from(content);
        entry.update_access();
        Some(Arc::new(entry))
    }

    #[inline]
    pub fn get_hit_status(&self, key: &CacheKey) -> Option<CacheHit> {
        if !self.settings.enabled {
            return None;
        }

        let entry_inner = self.entries.get(key)?;

        if entry_inner.entry.is_fresh {
            return Some(CacheHit::Hit);
        }

        if entry_inner.entry.is_stale_while_revalidate() {
            return Some(CacheHit::StaleWhileRevalidate);
        }

        if entry_inner.entry.is_stale_if_error() {
            return Some(CacheHit::Stale);
        }

        if entry_inner.entry.is_expired() {
            return Some(CacheHit::Expired);
        }

        None
    }

    pub async fn get_or_fetch<F, Fut>(
        &self,
        key: &CacheKey,
        fetch: F,
    ) -> Option<Arc<ProxyCacheEntry>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<(Bytes, StatusCode, HeaderMap, Option<Duration>)>>,
    {
        if let Some(entry) = self.get(key).await {
            return Some(entry);
        }

        let (content, status, headers, max_age) = fetch().await?;

        if self
            .insert(key.clone(), content, status.as_u16(), headers, max_age)
            .is_ok()
        {
            self.get(key).await
        } else {
            None
        }
    }

    pub fn insert(
        &self,
        key: CacheKey,
        content: Bytes,
        status: u16,
        headers: HeaderMap,
        max_age: Option<Duration>,
    ) -> Result<(), CacheError> {
        if !self.settings.enabled {
            return Err(CacheError::Disabled);
        }

        if !self.is_status_cacheable(status) {
            return Err(CacheError::NotCacheable);
        }

        let size = content.len();
        let swr = self.settings.stale_while_revalidate;
        let sie = self.settings.stale_if_error;
        let entry = ProxyCacheEntry::new(content.clone(), status, headers, max_age, swr, sie);

        let mut should_store_disk = false;
        let mut disk_path = None;

        if size > self.settings.max_memory_size {
            if self.settings.use_temp_file {
                should_store_disk = true;
            } else {
                return Err(CacheError::NotCacheable);
            }
        }

        if should_store_disk {
            let disk_path_clone = self.disk_path.clone();
            let key_clone = key.clone();
            let content_clone = content.clone();

            tokio::spawn(async move {
                let filename = Self::key_to_filename(&key_clone);
                let path = disk_path_clone.join(&filename);
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let _ = tokio::fs::write(&path, content_clone).await;
            });

            disk_path = Some(self.disk_path.join(Self::key_to_filename(&key)));
        }

        let checksum = CacheEntryInner::compute_checksum(&content);

        let entry_inner = CacheEntryInner {
            entry: Arc::new(entry),
            size,
            on_disk: should_store_disk,
            disk_path,
            checksum,
        };

        // Update memory size tracking atomically
        if let Some(old) = self.entries.get(&key) {
            if !old.on_disk {
                self.current_memory_size
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        v.checked_sub(old.size as u64)
                    })
                    .ok();
            }
        }

        if !should_store_disk {
            self.current_memory_size
                .fetch_add(size as u64, Ordering::Relaxed);
        }

        self.entries.insert(key.clone(), entry_inner);

        {
            let mut host_index = self.host_index.write();
            host_index.entry(key.host.clone()).or_default().push(key);
        }

        Ok(())
    }

    pub fn invalidate(&self, key: &CacheKey) {
        if let Some(entry) = self.entries.get(key) {
            if entry.on_disk {
                if let Some(path) = &entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }
            if !entry.on_disk {
                self.current_memory_size
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        v.checked_sub(entry.size as u64)
                    })
                    .ok();
            }
            self.entries.invalidate(key);
        }

        {
            let mut host_index = self.host_index.write();
            if let Some(keys) = host_index.get_mut(&key.host) {
                keys.retain(|k| k != key);
            }
        }
    }

    pub fn invalidate_by_pattern(&self, pattern: &str) -> usize {
        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(k, _)| k.uri.contains(pattern))
            .map(|(k, _)| (*k).clone())
            .collect();

        let count = to_remove.len();

        for key in &to_remove {
            if let Some(entry) = self.entries.get(key) {
                if entry.on_disk {
                    if let Some(path) = &entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                if !entry.on_disk {
                    self.current_memory_size
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(entry.size as u64)
                        })
                        .ok();
                }
                self.entries.invalidate(key);
            }
        }

        count
    }

    pub fn invalidate_by_host(&self, host: &str) -> usize {
        let to_remove: Vec<CacheKey> = {
            let host_index = self.host_index.read();
            host_index.get(host).cloned().unwrap_or_default()
        };

        let count = to_remove.len();

        for key in &to_remove {
            if let Some(entry) = self.entries.get(key) {
                if entry.on_disk {
                    if let Some(path) = &entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                if !entry.on_disk {
                    self.current_memory_size
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(entry.size as u64)
                        })
                        .ok();
                }
                self.entries.invalidate(key);
            }
        }

        {
            let mut host_index = self.host_index.write();
            host_index.remove(host);
        }

        count
    }

    pub fn clear(&self) {
        for (_, entry) in self.entries.iter() {
            if entry.on_disk {
                if let Some(path) = &entry.disk_path {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        self.entries.invalidate_all();
        self.current_memory_size.store(0, Ordering::Relaxed);
        self.host_index.write().clear();
    }

    pub fn stats(&self) -> CacheStats {
        self.entries.run_pending_tasks();

        let hit_count = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.entry.is_fresh)
            .count() as u64;

        let total = self.entries.entry_count();
        let miss_count = total.saturating_sub(hit_count);

        CacheStats {
            entries: total as usize,
            memory_size: self.current_memory_size.load(Ordering::Relaxed) as usize,
            disk_size: self.calculate_disk_size(),
            hits: hit_count,
            misses: miss_count,
        }
    }

    pub fn is_status_cacheable(&self, status: u16) -> bool {
        self.settings.valid_status.contains(&status)
    }

    pub async fn write_to_disk_async(&self, key: &CacheKey, content: Bytes) -> PathBuf {
        let filename = Self::key_to_filename(key);
        let path = self.disk_path.join(&filename);
        let parent = path.parent().map(|p| p.to_path_buf());
        let path_clone = path.clone();

        let _disk_path = self.disk_path.clone();

        tokio::spawn(async move {
            if let Some(parent) = parent {
                let _ = tokio::fs::create_dir_all(&parent).await;
            }
            let _ = tokio::fs::write(&path_clone, content).await;
        });

        path
    }

    fn key_to_filename(key: &CacheKey) -> String {
        use ahash::AHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = AHasher::default();
        key.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn calculate_disk_size(&self) -> usize {
        if !self.disk_path.exists() {
            return 0;
        }

        std::fs::read_dir(&self.disk_path)
            .map(|dir| {
                dir.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len() as usize)
                    .sum()
            })
            .unwrap_or(0)
    }

    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let inactive = self.settings.inactive;

        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, v)| {
                let age = now.duration_since(v.entry.created_at);
                age > inactive || v.entry.is_expired()
            })
            .map(|(k, _)| (*k).clone())
            .collect();

        let count = to_remove.len();

        for key in &to_remove {
            if let Some(entry) = self.entries.get(key) {
                if entry.on_disk {
                    if let Some(path) = &entry.disk_path {
                        let _ = std::fs::remove_file(path);
                    }
                }
                if !entry.on_disk {
                    self.current_memory_size
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            v.checked_sub(entry.size as u64)
                        })
                        .ok();
                }
                self.entries.invalidate(key);
            }
        }

        count
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
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

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub memory_size: usize,
    pub disk_size: usize,
    pub hits: u64,
    pub misses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, HeaderValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::Barrier;

    fn create_test_settings(temp_dir: &TempDir) -> ProxyCacheSettings {
        ProxyCacheSettings {
            enabled: true,
            path: temp_dir.path().join("cache"),
            max_memory_size: 1024 * 1024,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_secs(300),
            use_temp_file: true,
            valid_status: vec![200, 301, 302, 304],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        }
    }

    fn create_cache_key(host: &str, uri: &str) -> CacheKey {
        CacheKey {
            scheme: "https".to_string(),
            method: "GET".to_string(),
            host: host.to_string(),
            uri: uri.to_string(),
            vary: String::new(),
            site_id: "test_site".to_string(),
        }
    }

    fn create_test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/html"),
        );
        headers
    }

    fn create_test_entry(
        content: &[u8],
        status: u16,
        _max_age: Option<Duration>,
    ) -> (Bytes, u16, HeaderMap) {
        let bytes = Bytes::from(content.to_vec());
        (bytes, status, create_test_headers())
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let settings = ProxyCacheSettings {
            enabled: true,
            path: temp_dir.path().join("cache"),
            max_memory_size: 1024 * 1024,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_secs(300),
            use_temp_file: false,
            valid_status: vec![200],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        };

        let cache = ProxyCache::new(settings);
        let key = create_cache_key("example.com", "/test");

        let (content, status, headers) = create_test_entry(b"test content", 200, None);
        cache
            .insert(key.clone(), content, status, headers, None)
            .unwrap();

        let entry = cache.get(&key).await;
        assert!(
            entry.is_some(),
            "Entry should exist immediately after insert"
        );

        std::thread::sleep(Duration::from_millis(50));

        let entry_with_ttl = cache.get(&key).await;
        assert!(
            entry_with_ttl.is_some(),
            "Entry should exist before TTL expires"
        );
    }

    #[tokio::test]
    async fn test_ttl_expiration_with_max_age() {
        let temp_dir = TempDir::new().unwrap();
        let settings = ProxyCacheSettings {
            enabled: true,
            path: temp_dir.path().join("cache"),
            max_memory_size: 1024 * 1024,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_secs(300),
            use_temp_file: false,
            valid_status: vec![200],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        };

        let cache = ProxyCache::new(settings);
        let key = create_cache_key("example.com", "/expiring");

        let (content, status, headers) = create_test_entry(b"expiring content", 200, None);
        cache
            .insert(
                key.clone(),
                content,
                status,
                headers,
                Some(Duration::from_millis(10)),
            )
            .unwrap();

        let entry = cache.get(&key).await;
        assert!(
            entry.is_some(),
            "Entry should exist immediately after insert"
        );

        std::thread::sleep(Duration::from_millis(20));

        let entry_expired = cache.get(&key).await;
        assert!(
            entry_expired.is_none(),
            "Entry should be None after TTL expires"
        );
    }

    #[test]
    fn test_cache_invalidation_by_pattern() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        let key1 = create_cache_key("example.com", "/api/users");
        let key2 = create_cache_key("example.com", "/api/products");
        let key3 = create_cache_key("example.com", "/static/style.css");

        let (content1, status, headers) = create_test_entry(b"users data", 200, None);
        let (content2, status2, headers2) = create_test_entry(b"products data", 200, None);
        let (content3, status3, headers3) = create_test_entry(b"css content", 200, None);

        cache
            .insert(key1.clone(), content1, status, headers, None)
            .unwrap();
        cache
            .insert(key2.clone(), content2, status2, headers2, None)
            .unwrap();
        cache
            .insert(key3.clone(), content3, status3, headers3, None)
            .unwrap();

        let removed = cache.invalidate_by_pattern("/api/");
        assert_eq!(removed, 2, "Should remove 2 entries matching /api/ pattern");

        let stats = cache.stats();
        assert_eq!(stats.entries, 1, "Should have 1 entry remaining");
    }

    #[test]
    fn test_cache_invalidation_by_host() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        let key1 = create_cache_key("host1.example.com", "/page1");
        let key2 = create_cache_key("host1.example.com", "/page2");
        let key3 = create_cache_key("host2.example.com", "/page3");

        let (content1, status, headers) = create_test_entry(b"host1 page1", 200, None);
        let (content2, status2, headers2) = create_test_entry(b"host1 page2", 200, None);
        let (content3, status3, headers3) = create_test_entry(b"host2 page3", 200, None);

        cache
            .insert(key1.clone(), content1, status, headers, None)
            .unwrap();
        cache
            .insert(key2.clone(), content2, status2, headers2, None)
            .unwrap();
        cache
            .insert(key3.clone(), content3, status3, headers3, None)
            .unwrap();

        let removed = cache.invalidate_by_host("host1.example.com");
        assert_eq!(removed, 2, "Should remove 2 entries for host1.example.com");

        let stats = cache.stats();
        assert_eq!(stats.entries, 1, "Should have 1 entry remaining");

        cache.invalidate_by_host("nonexistent.example.com");
        let stats2 = cache.stats();
        assert_eq!(
            stats2.entries, 1,
            "Should still have 1 entry (nonexistent host)"
        );
    }

    #[test]
    fn test_invalidate_single_entry() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        let key = create_cache_key("example.com", "/test");
        let (content, status, headers) = create_test_entry(b"test content", 200, None);
        cache
            .insert(key.clone(), content, status, headers, None)
            .unwrap();

        let stats_before = cache.stats();
        assert_eq!(stats_before.entries, 1);

        cache.invalidate(&key);

        let stats_after = cache.stats();
        assert_eq!(stats_after.entries, 0);
    }

    #[test]
    fn test_clear_all_entries() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        for i in 0..5 {
            let key = create_cache_key("example.com", &format!("/test{}", i));
            let (content, status, headers) = create_test_entry(b"test content", 200, None);
            cache.insert(key, content, status, headers, None).unwrap();
        }

        let stats_before = cache.stats();
        assert_eq!(stats_before.entries, 5);

        cache.clear();

        let stats_after = cache.stats();
        assert_eq!(stats_after.entries, 0);
        assert_eq!(stats_after.memory_size, 0);
    }

    #[tokio::test]
    async fn test_disk_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("cache");
        std::fs::create_dir_all(&cache_path).unwrap();

        let settings = ProxyCacheSettings {
            enabled: true,
            path: cache_path.clone(),
            max_memory_size: 50,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_secs(300),
            use_temp_file: true,
            valid_status: vec![200],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        };

        let cache1 = ProxyCache::new(settings);
        let key = create_cache_key("example.com", "/disk-test");

        let large_content = vec![0u8; 200];
        let (content, status, headers) = create_test_entry(&large_content, 200, None);
        cache1
            .insert(key.clone(), content, status, headers, None)
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let files_after_insert = std::fs::read_dir(&cache_path).unwrap().count();
        assert!(
            files_after_insert > 0,
            "Should have created disk file for large content"
        );
    }

    #[test]
    fn test_memory_eviction_on_capacity() {
        let temp_dir = TempDir::new().unwrap();
        let settings = ProxyCacheSettings {
            enabled: true,
            path: temp_dir.path().join("cache"),
            max_memory_size: 100,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_secs(300),
            use_temp_file: false,
            valid_status: vec![200],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        };

        let cache = ProxyCache::new(settings);

        for i in 0..10 {
            let key = create_cache_key("example.com", &format!("/large{}", i));
            let content = vec![0u8; 50];
            let (bytes, status, headers) = create_test_entry(&content, 200, None);
            let _ = cache.insert(key, bytes, status, headers, None);
        }

        let stats = cache.stats();
        assert!(
            stats.entries <= 5,
            "Cache should evict entries when capacity exceeded"
        );
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = Arc::new(ProxyCache::new(settings));

        let num_keys = 20;
        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let cache_clone = cache.clone();
            let barrier_clone = barrier.clone();
            let counter_clone = counter.clone();

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;

                for i in 0..num_keys {
                    let key =
                        create_cache_key(&format!("host{}.com", thread_id), &format!("/item{}", i));
                    let (content, status, headers) =
                        create_test_entry(b"concurrent content", 200, None);

                    let _ = cache_clone.insert(key.clone(), content, status, headers, None);
                    let _ = cache_clone.get(&key).await;
                }

                counter_clone.fetch_add(1, Ordering::Relaxed);
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        assert_eq!(counter.load(Ordering::Relaxed), num_threads);

        let stats = cache.stats();
        assert!(
            stats.entries > 0,
            "Cache should have entries after concurrent access"
        );
    }

    #[tokio::test]
    async fn test_concurrent_insert_same_key() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = Arc::new(ProxyCache::new(settings));

        let key = create_cache_key("example.com", "/concurrent");
        let barrier = Arc::new(Barrier::new(10));
        let mut handles = vec![];

        for _ in 0..10 {
            let cache_clone = cache.clone();
            let barrier_clone = barrier.clone();
            let key_clone = key.clone();
            let content = format!("content from thread {}", 0);

            let handle = tokio::spawn(async move {
                barrier_clone.wait().await;

                let (bytes, status, headers) = create_test_entry(content.as_bytes(), 200, None);
                let _ = cache_clone.insert(key_clone, bytes, status, headers, None);
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let entry = cache.get(&key).await;
        assert!(entry.is_some(), "Should have an entry for the key");
    }

    #[test]
    fn test_cache_stats() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        let key1 = create_cache_key("example.com", "/page1");
        let key2 = create_cache_key("example.com", "/page2");

        let (content1, status, headers) = create_test_entry(b"content1", 200, None);
        let (content2, status2, headers2) = create_test_entry(b"content2", 200, None);

        cache
            .insert(key1.clone(), content1, status, headers, None)
            .unwrap();
        cache
            .insert(key2.clone(), content2, status2, headers2, None)
            .unwrap();

        let stats = cache.stats();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.memory_size, 16);

        cache.invalidate(&key1);
        let stats_after = cache.stats();
        assert_eq!(stats_after.entries, 1);
    }

    #[test]
    fn test_is_status_cacheable() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        assert!(cache.is_status_cacheable(200));
        assert!(cache.is_status_cacheable(301));
        assert!(!cache.is_status_cacheable(404));
        assert!(!cache.is_status_cacheable(500));
    }

    #[test]
    fn test_cache_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let settings = ProxyCacheSettings {
            enabled: false,
            path: temp_dir.path().join("cache"),
            max_memory_size: 1024 * 1024,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_secs(300),
            use_temp_file: false,
            valid_status: vec![200],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        };
        let cache = ProxyCache::new(settings);

        let key = create_cache_key("example.com", "/test");
        let (content, status, headers) = create_test_entry(b"test", 200, None);

        let result = cache.insert(key, content, status, headers, None);
        assert!(matches!(result, Err(CacheError::Disabled)));
    }

    #[test]
    fn test_proxy_cache_entry_is_expired() {
        let entry = ProxyCacheEntry::new(
            Bytes::from_static(b"test"),
            200,
            HeaderMap::new(),
            Some(Duration::from_secs(0)),
            None,
            None,
        );

        std::thread::sleep(Duration::from_millis(10));
        assert!(entry.is_expired(), "Entry with 0s TTL should be expired");
    }

    #[test]
    fn test_proxy_cache_entry_not_expired_without_max_age() {
        let entry = ProxyCacheEntry::new(
            Bytes::from_static(b"test"),
            200,
            HeaderMap::new(),
            None,
            None,
            None,
        );

        assert!(
            !entry.is_expired(),
            "Entry without max_age should not be expired"
        );
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let temp_dir = TempDir::new().unwrap();
        let settings = ProxyCacheSettings {
            enabled: true,
            path: temp_dir.path().join("cache"),
            max_memory_size: 1024 * 1024,
            max_disk_size: 10 * 1024 * 1024,
            inactive: Duration::from_millis(20),
            use_temp_file: false,
            valid_status: vec![200],
            methods: vec!["GET".to_string()],
            use_stale: vec![],
            stale_while_revalidate: None,
            stale_if_error: None,
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$site_id$request_uri".to_string(),
            vary_by: vec![],
        };

        let cache = ProxyCache::new(settings);
        let key = create_cache_key("example.com", "/cleanup-test");

        let (content, status, headers) = create_test_entry(b"test", 200, None);
        cache
            .insert(
                key.clone(),
                content,
                status,
                headers,
                Some(Duration::from_millis(10)),
            )
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        let removed = cache.cleanup_expired();
        assert!(removed >= 1, "Should remove at least 1 expired entry");

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
    }

    #[test]
    fn test_cache_hit_status() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        let key = create_cache_key("example.com", "/hit-status");

        let (content, status, headers) = create_test_entry(b"test", 200, None);
        cache
            .insert(key.clone(), content, status, headers, None)
            .unwrap();

        let hit_status = cache.get_hit_status(&key);
        assert!(matches!(hit_status, Some(CacheHit::Hit)));

        cache.invalidate(&key);
        let miss_status = cache.get_hit_status(&key);
        assert!(miss_status.is_none());
    }

    #[test]
    fn test_cache_hit_rate() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        cache.record_cache_hit();
        cache.record_cache_hit();
        cache.record_cache_miss();

        let rate = cache.cache_hit_rate();
        assert!(
            (rate - 66.66).abs() < 0.1,
            "Hit rate should be approximately 66.66%"
        );
    }

    #[test]
    fn test_clone_cache() {
        let temp_dir = TempDir::new().unwrap();
        let settings = create_test_settings(&temp_dir);
        let cache = ProxyCache::new(settings);

        let key = create_cache_key("example.com", "/clone-test");
        let (content, status, headers) = create_test_entry(b"test", 200, None);
        cache.insert(key, content, status, headers, None).unwrap();

        let cache2 = cache.clone();
        let stats = cache2.stats();
        assert_eq!(stats.entries, 1);
    }
}
