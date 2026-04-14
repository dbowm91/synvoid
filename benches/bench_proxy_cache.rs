use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::hash_map::DefaultHasher;
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
}

fn benchmark_hashmap_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashmap_insert");
    for size in [100, 1_000, 10_000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let mut map: HashMap<CacheKey, CacheEntry> = HashMap::new();
                for i in 0..size {
                    let key =
                        CacheKey::new("https", "GET", &format!("example{}.com", i % 100), "/path");
                    map.insert(
                        key,
                        CacheEntry {
                            data: vec![0u8; 1000],
                            created_at: Instant::now(),
                        },
                    );
                }
            });
        });
    }
    group.finish();
}

fn benchmark_cache_get(c: &mut Criterion) {
    let mut map: HashMap<CacheKey, CacheEntry> = HashMap::new();
    for i in 0..1_000 {
        let key = CacheKey::new("https", "GET", &format!("example{}.com", i), "/path");
        map.insert(
            key,
            CacheEntry {
                data: vec![0u8; 1000],
                created_at: Instant::now(),
            },
        );
    }

    let mut group = c.benchmark_group("cache_get");
    group.bench_function("hashmap_lookup", |b| {
        b.iter(|| {
            let key = CacheKey::new("https", "GET", "example500.com", "/path");
            map.get(&key)
        });
    });
    group.finish();
}

fn benchmark_lru_invalidate(c: &mut Criterion) {
    let mut cache = SimpleCache::new();
    for i in 0..1_000 {
        let key = CacheKey::new("https", "GET", &format!("example{}.com", i), "/path");
        cache.insert(
            key,
            CacheEntry {
                data: vec![0u8; 1000],
                created_at: Instant::now(),
            },
        );
    }

    c.bench_function("lru_invalidate", |b| {
        b.iter(|| {
            let key = CacheKey::new("https", "GET", "example500.com", "/path");
            cache.invalidate(&key);
        });
    });
}

fn benchmark_hasher(c: &mut Criterion) {
    let data = "https://example.com/path/to/resource?query=value#fragment";
    c.bench_function("default_hasher_siphash", |b| {
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            hasher.finish()
        });
    });
}

criterion_group!(
    benches,
    benchmark_hashmap_insert,
    benchmark_cache_get,
    benchmark_lru_invalidate,
    benchmark_hasher
);
criterion_main!(benches);
