//! Serialization derive utilities and migration guide
//!
//! This module documents the pattern for migrating from serde to rkyv serialization.
//!
//! ## Current State
//!
//! - **serde** (bincode): Current serialization format for IPC and QUIC messages
//! - **rkyv**: Zero-copy deserialization - planned migration
//!
//! ## Migration to rkyv
//!
//! rkyv provides zero-copy deserialization which is significantly faster than serde.
//! However, it requires types to be specifically compatible with rkyv's archive format.
//!
//! ### Step 1: Enable rkyv feature
//!
//! ```toml
//! # Cargo.toml
//! [features]
//! rkyv = ["synvoid/rkyv"]
//! ```
//!
//! ### Step 2: Identify compatible types
//!
//! Not all serde types are rkyv-compatible. Compatible types include:
//! - Primitives (u8, u32, String, Vec<u8>, etc.)
//! - Structs with rkyv-compatible fields
//! - Enums with primitive discriminants
//!
//! Types that require special handling:
//! - `std::collections::HashMap` → `rkyv::collections::HashMap`
//! - `std::collections::HashSet` → `rkyv::collections::HashSet`
//! - `chrono::DateTime` → Custom wrapper or rkyv::time
//! - `regex::Regex` → Cannot be archived (serialize to bytes)
//! - Types with internal mutability → Cannot be archived
//!
//! ### Step 3: Add rkyv derives to compatible types
//!
//! For each type used in IPC/QUIC serialization:
//!
//! ```rust
//! // Before (serde only)
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct MyMessage {
//!     pub id: u64,
//!     pub data: Vec<u8>,
//! }
//!
//! // After (serde + rkyv)
//! use serde::{Deserialize, Serialize};
//! #[cfg(feature = "rkyv")]
//! use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
//!
//! #[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
//! #[derive(Serialize, Deserialize)]
//! pub struct MyMessage {
//!     pub id: u64,
//!     pub data: Vec<u8>,
//! }
//! ```
//!
//! ### Step 4: Update serialization.rs
//!
//! Replace bincode calls with rkyv API:
//!
//! ```rust
//! // Use rkyv::to_bytes for serialization
//! // Use rkyv::from_bytes for deserialization
//! ```
//!
//! ### Step 5: Use checked deserialization for external data
//!
//! ```rust
//! // For QUIC mesh messages (external, untrusted)
//! let msg = crate::serialization::deserialize_checked::<T>(&data)?;
//!
//! // For IPC (local, trusted)
//! let msg = crate::serialization::deserialize::<T>(&data)?;
//! ```
//!
//! ## Critical Path Types (Priority for Migration)
//!
//! These types are used in IPC and should be migrated first:
//!
//! 1. **src/process/ipc.rs** - Master↔Worker messages
//!    - `MasterCommand`, `MasterStatus`, `WorkerStatusInfo`
//!    - `Message` enum (all variants)
//!    - `WorkerMetricsPayload`
//!
//! 2. **src/tunnel/quic/messages.rs** - QUIC tunnel messages
//!    - `TunnelMessage` enum
//!    - `PortMapping`, `DataChunkHeader`
//!
//! ## Known Migration Challenges
//!
//! - `HashMap<String, u64>` in metrics → Use rkyv collections
//! - `DateTime<Utc>` → Custom serialization or rkyv::time
//! - Complex enums with data → Ensure all variants are archivable
//!
//! ## Verification
//!
//! Test migration with:
//! ```bash
//! cargo check --features rkyv
//! ```
//!
//! Fix compilation errors by either:
//! 1. Making types rkyv-compatible
//! 2. Using `#[cfg_attr(feature = "rkyv", skip)]` for incompatible fields
//! 3. Implementing custom `Archive` implementations

#[cfg(feature = "rkyv")]
pub mod rkyv {
    pub use rkyv::{Archive, Deserialize, Serialize};
}
