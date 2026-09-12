//! Low-capability mesh wire/identity/signature vocabulary.
//!
//! Phase 27 extraction boundary. This crate owns stable peer wire vocabulary
//! and synchronous deterministic verification primitives with **no** runtime
//! service ownership.
//!
//! ## Dependency budget (enforced by repo guards)
//!
//! Allowed:
//! - `serde` / `postcard` (wire serialization vocabulary only)
//! - `ed25519-dalek`, `subtle`, `sha2` (verification primitives)
//! - `base64`, `rand` (key/signature encoding, nonce generation)
//! - `thiserror` (typed contract errors)
//! - `rkyv` 0.8 (typed archived structs, never `serde_json::Value`)
//!
//! Forbidden (must never appear in `Cargo.toml` or `use` paths):
//! - `synvoid-mesh`, root `synvoid`
//! - `openraft`, `rusqlite`
//! - QUIC/Hyper/Axum/Tonic server runtimes (generated message types excluded;
//!   this crate owns no generated protobufs in Phase 27)
//! - `yara-x` / YARA execution
//! - proxy/tunnel/serverless implementations
//! - mesh persistence or policy managers (`synvoid-config`, `synvoid-block-store`,
//!   `synvoid-proxy`, `synvoid-tunnel`, `synvoid-serverless`, `pqc` runtime pools)
//!
//! ## What lives here (classes 1-2)
//!
//! - wire constants (`MESH_MESSAGE_VERSION`, replay window, framing bounds)
//! - `HybridSignature` canonical envelope (value type only, no ML-DSA runtime)
//! - `ProtocolSigner` Ed25519 value semantics + free-function verification
//! - `ReplayProtection` / `ReplayResult` (synchronous, injectable clock)
//! - stable wire enums (`MessageCategory`, `AckStatus`, threat taxonomy, ...)
//! - `ThreatIndicator` value struct (no policy, no storage)
//! - length-prefix framing helpers (bounded, fail-closed)
//!
//! ## What stays in `synvoid-mesh` (classes 3-5)
//!
//! - `MeshMessageSigner` runtime service (hybrid/PQ signing, `CryptoVerificationPool`
//!   offload, async verification) — implements verification **over** these value types
//! - `CryptoVerificationPool`, `MeshMlDsaSigner/Verifier`, key managers
//! - `MeshMessage` full enum, protobuf encode/decode, compression, DHT/Raft/policy
//! - transport implementation (QUIC/TCP), persistence, YARA distribution
//!
//! Wire compatibility: serde representations of moved types are byte-identical to
//! their `synvoid-mesh` predecessors (same variant order, same field order, same
//! derives minus non-wire `schemars::JsonSchema`). See `tests/golden_vectors.rs`
//! and the differential suite in `synvoid-mesh`.

pub mod constants;
pub mod framing;
pub mod hybrid;
pub mod replay;
pub mod signer;
pub mod threat;
pub mod time;
pub mod wire;

pub use constants::{
    COMPRESSION_THRESHOLD, MAX_REPLAY_CACHE_SIZE, MAX_WIRE_MESSAGE_SIZE, MESH_MESSAGE_VERSION,
    NONCE_SIZE, PRIORITY_TIER_ENTERPRISE, PRIORITY_TIER_FREE, PRIORITY_TIER_PAID,
    PRIORITY_TIER_PREMIUM, REPLAY_WINDOW_SECS,
};
pub use framing::{decode_with_length_prefix, encode_with_length_prefix, FrameError};
pub use hybrid::{
    HybridSignature, HybridSignatureError, ED25519_SIGNATURE_SIZE, ML_DSA_SIGNATURE_SIZE,
};
pub use replay::{ReplayProtection, ReplayResult};
pub use signer::{ProtocolSigner, SignatureError};
pub use threat::ThreatIndicator;
pub use wire::{
    AckStatus, AnnounceAction, GlobalNodeAction, HealthStatus, LookupType, MessageCategory,
    ProtocolError, ThreatSeverity, ThreatType, WasmModuleType,
};
