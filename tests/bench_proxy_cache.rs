use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::Instant;

#[derive(Clone, PartialEq, Eq)]
pub struct CacheKey {
    scheme: String,
    method: String,
    host: String,
    uri: String,
}

impl CacheKey {
    pub fn new(scheme: &str, method: &str, host: &str, uri: &str) -> Self {
        Self {
            scheme: scheme.to_string(),
            method: method.to_string(),
            host: host.to_string(),
            uri: uri.to_string(),
        }
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scheme.hash(state);
        self.method.hash(state);
        self.host.hash(state);
        self.uri.hash(state);
    }
}

pub struct CacheEntry {
    pub data: Vec<u8>,
    pub created_at: Instant,
}

pub struct SimpleCache {
    entries: HashMap<CacheKey, CacheEntry>,
    access_order: VecDeque<CacheKey>,
}

impl SimpleCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<&CacheEntry> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: CacheKey, entry: CacheEntry) {
        if self.access_order.contains(&key) {
            self.access_order.retain(|k| k != &key);
        }
        self.access_order.push_back(key.clone());
        self.entries.insert(key, entry);
    }

    pub fn invalidate(&mut self, key: &CacheKey) {
        self.entries.remove(key);
        self.access_order.retain(|k| k != key);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn evict_lru(&mut self, count: usize) {
        for _ in 0..count {
            if let Some(key) = self.access_order.pop_front() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&CacheKey, &CacheEntry) -> bool,
    {
        let keys_to_remove: Vec<_> = self
            .entries
            .iter()
            .filter(|(k, v)| !f(k, v))
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_remove {
            self.invalidate(&key);
        }
    }
}

fn main() {
    println!("Running proxy cache benchmarks...\n");

    println!("=== HashMap Insert Benchmark ===");
    let mut map: HashMap<CacheKey, CacheEntry> = HashMap::new();

    let start = Instant::now();
    for i in 0..10_000 {
        let key = CacheKey::new("https", "GET", &format!("example{}.com", i % 100), "/path");
        map.insert(
            key,
            CacheEntry {
                data: vec![0u8; 1000],
                created_at: Instant::now(),
            },
        );
    }
    let elapsed = start.elapsed();
    println!(
        "  Insert 10K entries: {:.3}ms",
        elapsed.as_secs_f64() * 1000.0
    );

    println!("\n=== Cache Get Benchmark ===");
    let start = Instant::now();
    for i in 0..100_000 {
        let key = CacheKey::new("https", "GET", &format!("example{}.com", i % 100), "/path");
        let _ = map.get(&key);
    }
    let elapsed = start.elapsed();
    println!(
        "  Get 100K lookups: {:.3}ms ({:.3}ns/op)",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
    );

    println!("\n=== LRU Benchmark (CURRENT - INEFFICIENT) ===");
    let mut cache = SimpleCache::new();

    for i in 0..1000 {
        let key = CacheKey::new("https", "GET", &format!("example{}.com", i), "/path");
        cache.insert(
            key,
            CacheEntry {
                data: vec![0u8; 1000],
                created_at: Instant::now(),
            },
        );
    }

    let start = Instant::now();
    for _ in 0..1000 {
        let key = CacheKey::new("https", "GET", "example500.com", "/path");
        cache.invalidate(&key);
    }
    let elapsed = start.elapsed();
    println!(
        "  Invalidate (VecDeque::retain): {:.3}ms for 1000 ops",
        elapsed.as_secs_f64() * 1000.0
    );

    println!("\n=== DefaultHasher vs FxHasher Benchmark ===");
    use std::collections::hash_map::DefaultHasher;

    let data = "https://example.com/path/to/resource?query=value#fragment";

    let start = Instant::now();
    for _ in 0..1_000_000 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let _ = hasher.finish();
    }
    let elapsed = start.elapsed();
    println!(
        "  DefaultHasher (SipHash): {:.3}ns/op (1M ops)",
        elapsed.as_secs_f64() * 1_000_000_000.0 / 1_000_000.0
    );

    println!("\n=== Memory Size Benchmark ===");
    let entries_count = 10_000;
    let entry_size = 1000;

    let map: HashMap<String, Vec<u8>> = (0..entries_count)
        .map(|i| (format!("key_{}", i), vec![0u8; entry_size]))
        .collect();

    let bytes = entries_count * (32 + entry_size);
    println!(
        "  {} entries x {} bytes = {:.2} MB estimated",
        entries_count,
        entry_size,
        bytes as f64 / 1_048_576.0
    );

    println!("\nDone!");
}
