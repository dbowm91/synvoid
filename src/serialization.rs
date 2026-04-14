//! Serialization abstraction layer
//!
//! This module provides serialization using postcard for IPC and QUIC messages.
//!
//! ## Why Postcard?
//!
//! - Drop-in replacement for bincode with better maintenance
//! - 30% smaller serialized output
//! - No_std compatible
//! - Actively maintained
//!
//! ## Usage
//!
//! ```rust
//! use crate::serialization::{serialize, deserialize};
//!
//! let data = serialize(&my_message)?;
//! let msg = deserialize::<MyMessage>(&data)?;
//! ```

use std::io::{self, ErrorKind};

/// Serialize a value to bytes using postcard
pub fn serialize<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

/// Deserialize bytes to a value using postcard
pub fn deserialize<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    postcard::from_bytes(data).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

/// Serialize for untrusted data (external sources like QUIC mesh)
/// Currently same as serialize - postcard handles this well
pub fn serialize_checked<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serialize(value)
}

/// Deserialize for untrusted data (external sources like QUIC mesh)
/// Currently same as deserialize
pub fn deserialize_checked<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    deserialize(data)
}

/// Legacy API compatibility using postcard
pub fn serialize_bincode<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serialize(value)
}

/// Legacy API compatibility using postcard
pub fn deserialize_bincode<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    deserialize(data)
}

/// Get serialized size
pub fn serialized_size<T: serde::Serialize>(value: &T) -> io::Result<usize> {
    let bytes = serialize(value)?;
    Ok(bytes.len())
}
