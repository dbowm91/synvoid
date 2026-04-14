//! HTTP response caching layer.
//!
//! Provides an LRU cache for proxied HTTP responses with support for
//! cache key generation, TTL-based expiration, and Cache-Control parsing.

pub mod config;
pub mod key;
pub mod store;

pub use config::ProxyCacheSettings;
pub use key::{CacheKey, CacheKeyBuilder};
pub use store::{CacheHit, ProxyCache, ProxyCacheEntry};
