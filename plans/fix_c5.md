# Plan: Fix C.5 JSON Serialization Migration

## Objective
Fix the compilation errors introduced by the previous agent's partial migration of Mesh DHT from `serde_json` to `postcard` (via `crate::serialization`) and complete the C.5 task.

## Key Files & Context
- `src/mesh/dht/record_store_crud.rs` and `src/mesh/dht/record_store_dns.rs` (missing imports)
- `src/mesh/topology/types.rs` (missing `rkyv` derives for `PeerScore` and `PeerState`)
- `src/mesh/dht/record_store_sync.rs` (byte-to-string conversion errors)
- `src/dns/mesh_sync/health.rs` (needs update from `serde_json::Value` to `AnycastNode` struct)
- `src/mesh/threat_intel.rs`, `src/mesh/yara_rules.rs`, `src/mesh/topology.rs` (remaining `serde_json` migrations)
- `src/mesh/protocol.rs` (update `MeshMessageSigner::verify` to accept `&[u8]`)

## Implementation Steps
1. **Fix Missing Imports:**
   - Add `use crate::mesh::dht::GlobalNodeKeyRecord;` to `record_store_crud.rs`.
   - Add `use crate::mesh::dht::{DnsDomainRegistration, AnycastNode};` to `record_store_dns.rs`.

2. **Fix Rkyv Trait Bounds:**
   - Add `#[derive(Archive, Serialize, Deserialize)]` (from `rkyv`) to `PeerScore` and `PeerState` in `src/mesh/topology/types.rs`.
   - Ensure fields like `std::time::Instant` use `#[rkyv(with = ...)]` or `#[rkyv(omit_bounds)]` / `#[rkyv(skip)]` depending on if they need to be persisted. Given they are internal state, we may be able to ignore or transform them.

3. **Fix String Conversions:**
   - In `src/mesh/dht/record_store_sync.rs`, replace `.as_str()` calls on `Vec<u8>` with proper UTF-8 conversion if necessary, or change the `verify` functions to accept `&[u8]`. The `MeshMessageSigner::verify` method should likely take `&[u8]` instead of `&str`.

4. **Refactor DNS Health Sync:**
   - Update `src/dns/mesh_sync/health.rs` to read properties from the `AnycastNode` struct instead of parsing `serde_json::Value` keys.

5. **Complete C.5 Migration:**
   - Search for `serde_json` in `src/mesh/` and replace the serialization/deserialization calls with `crate::serialization::serialize` / `deserialize`.
   - Ensure specific record types (like `ThreatIndicator`) are passed correctly into the serialization wrapper.

6. **Verification & Testing:**
   - `cargo check` to ensure all 31 compilation errors are resolved.
   - `cargo clippy --lib -- -D warnings`.
   - `cargo test --test dht_integration_test` to verify DHT record persistence functionality is not broken.

7. **Update Status:**
   - Mark C.5 as complete in `plans/plan.md`.