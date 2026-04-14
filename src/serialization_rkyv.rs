//! High-performance serialization for DNS and DHT
//!
//! This module provides utilities for adding rkyv zero-copy serialization to
//! performance-critical types like DNS records and DHT data structures.
//!
//! ## Why rkyv for DNS/DHT?
//!
//! DNS and DHT operations handle high volumes of requests where:
//! - Zero-copy deserialization eliminates allocation overhead
//! - Lower memory pressure enables higher throughput
//! - Better cache efficiency for frequently accessed data
//!
//! ## Usage
//!
//! 1. Add rkyv derives to your types:
//!
//! ```rust
//! use serde::{Deserialize, Serialize};
//! use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
//!
//! #[derive(Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
//! pub struct DnsRecord {
//!     pub name: String,
//!     pub ttl: u32,
//!     // ...
//! }
//! ```
//!
//! 2. Use rkyv directly for serialization:
//!
//! ```rust
//! use rkyv::to_bytes;
//!
//! // Serialize
//! let bytes = to_bytes(&record).unwrap().into_vec();
//!
//! // Deserialize (zero-copy - returns reference into archived data)
//! let archived = rkyv::archived_root::<DnsRecord>(&bytes).unwrap();
//! ```

use std::io::{self, ErrorKind};

/// Serialize using postcard (default for compatibility)
pub fn serialize<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

/// Deserialize using postcard (default for compatibility)
pub fn deserialize<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    postcard::from_bytes(data).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

/// Get serialized size
pub fn serialized_size<T: serde::Serialize>(value: &T) -> io::Result<usize> {
    serialize(value).map(|v| v.len())
}

// Re-export rkyv for convenience
pub use rkyv;
