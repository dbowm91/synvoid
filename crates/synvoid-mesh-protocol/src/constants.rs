//! Stable wire constants. Byte-compatibility anchors for Phase 27.
//!
//! Values are copied verbatim from `synvoid-mesh/src/mesh/protocol.rs`.
//! Do not change without an explicit protocol-version migration.

/// Current mesh message wire version.
pub const MESH_MESSAGE_VERSION: u8 = 1;
/// Payloads at or above this size are eligible for compression in `synvoid-mesh`
/// (compression itself stays in `synvoid-mesh`; this constant is shared so both
/// layers agree on the threshold).
pub const COMPRESSION_THRESHOLD: usize = 512;
/// Nonce size in bytes for handshake/route messages.
pub const NONCE_SIZE: usize = 16;
/// Replay window in seconds.
pub const REPLAY_WINDOW_SECS: u64 = 60;
/// Bound on the replay nonce cache.
pub const MAX_REPLAY_CACHE_SIZE: usize = 10000;

/// Absolute bound for length-prefixed wire frames decoded by this crate.
/// Matches the transport-layer `MAX_MESSAGE_SIZE` (10 MiB) in `synvoid-mesh`.
pub const MAX_WIRE_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Priority tiers (stable wire values).
pub const PRIORITY_TIER_FREE: u32 = 0;
pub const PRIORITY_TIER_PAID: u32 = 1;
pub const PRIORITY_TIER_PREMIUM: u32 = 2;
pub const PRIORITY_TIER_ENTERPRISE: u32 = 3;
