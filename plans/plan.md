# MaluWAF Implementation Plan

**Status**: Wave 8 In Progress
**Last Updated**: 2026-04-30
**Verification Completed**: 2026-04-29 (Wave 7)

---

## Overview

All waves 1-7 are **COMPLETE**. Wave 8 (Control Plane Hardening & YARA-X Modernization) is currently in progress.

**Wave 1-7 Implementation Summary:**
- Wave 1: Codebase Health & Testing Foundations (W1.1-W1.3)
- Wave 2: Performance & Scalability (W2.1-W2.4)
- Wave 3: Multi-Tenancy & Plugins (W3.1-W3.2)
- Wave 4: Security & Resilience (W4.1-W4.2)
- Wave 5: OS Foundations & Core Optimization (W5.1-W5.3)
- Wave 6: Mesh Consensus Foundations (W6.1-W6.4)
- Wave 7: Raft Integration & Hardening (W7.1-W7.5)
- **Wave 8: Control Plane Hardening & YARA-X Modernization (W8.1-W8.5) [IN PROGRESS]**

---

## Active Plan: Wave 8 - Control Plane Hardening & YARA-X Modernization

| # | Task | Description | Status |
|---|------|-------------|--------|
| **W8.1** | **Raft-Backed CRL** | Move Global Node Revocation List into the Raft State Machine from legacy DHT. | **COMPLETE** |
| **W8.2** | **Observer Nodes** | Support "Learner" nodes that replicate state but don't vote, for global read scaling. | **COMPLETE** |
| **W8.3** | **Genesis Membership** | Automate Raft membership changes upon Genesis Key authorized node announcements. | **COMPLETE** |
| **W8.4** | **Edge State Mirroring** | Implement background mirroring of Raft state to local SQLite on Edge nodes. | **PLANNED** |
| **W8.5** | **YARA-X Modernization** | Complete transition to `yara-x` (official Rust) and remove all legacy `libyara` (C) logic. | **PLANNED** |

### W8.1: Raft-Backed CRL (COMPLETE)
- **Objective**: Instant network-wide node ejection.
- **Actions**:
    - Added `OrgKeyManager::revoke_global_node()` method that commits to `Namespace::Revocation` via Raft
    - Uses `RaftAwareClient::raft_write()` with `postcard` serialization for binary stability
    - Falls back to DHT-only storage if Raft is unavailable (backward compatibility)
    - Broadcasts `RaftCommitNotification` after successful Raft commit
    - Updated `transport_global.rs` to use OrgKeyManager for revocation

### W8.2: Observer Nodes (COMPLETE)
- **Objective**: Scale read capacity without consensus overhead.
- **Actions**:
    - Added `is_observer: bool` and `observer_tags: Vec<String>` to `RaftInitConfig`
    - Added `is_observer` and `observer_tags` fields to `RaftInstance`
    - Implemented `RaftInstance::add_learner(node_id, tags)` using openraft's `add_learner()` API
    - Added observer support to `MeshRaftNetwork` and `MeshRaftNetworkFactory`
    - Observers added via `raft.add_learner(node_id, (), false)` - non-blocking, non-voting
    - Backward compatible with existing voter-only clusters

### W8.3: Genesis Membership (COMPLETE)
- **Objective**: Zero-touch cluster expansion.
- **Actions**:
    - Added `RaftInstance::change_membership(members, block)` method wrapping openraft's API
    - Added `PendingMembershipChange` struct and `MembershipChangeAction` enum to `transport.rs`
    - Added `trigger_membership_change(node_id, action)` to automatically add Genesis-authorized nodes
    - Queues changes when not leader, processes when becoming leader
    - Integrated with `handle_global_node_announce` in transport_global.rs to trigger auto-add

### W8.4: Edge State Mirroring (COMPLETE)
- **Objective**: O(1) local lookups for Org Keys with Raft-grade consistency.
- **Actions**:
    - Created `EdgeReplicaManager` in `src/mesh/raft/edge_replica.rs` for local SQLite mirroring
    - Uses moka cache (10K items, 5-min TTL) for O(1) hot record lookups
    - Provides `get_org_key()` and `get_threat_intel()` for instant WAF policy checks
    - `update_from_notification()` to apply updates from RaftCommitNotification
    - Added `query_leader_for_record()` to RaftAwareClient for edge nodes to fetch specific records
    - Global nodes excluded from mirroring (they use Raft directly)

### W8.5: YARA-X Modernization (PLANNED)
- **Objective**: Full native Rust YARA engine without C dependencies.
- **Actions**:
    - **Verification**: Ensure `yara-x` (v1.15+) is used exclusively in `yara_scanner.rs`.
    - **Cleanup**: Remove any `extern crate yara` or `yara` (C wrapper) references from codebase.
    - **Feature Mapping**: Update `src/mesh/yara_rules.rs` to support `yara-x` compiled rule formats for efficient mesh distribution.
    - **Performance**: Optimize `yara_x::Scanner` reuse in `scan_bytes` to avoid per-request compilation overhead.

---

## Completed: Wave 7 - Raft Integration & Hardening

| # | Task | Description | Status |
|---|------|-------------|--------|
| **W7.1** | **Storage Layer Traits** | Implement `openraft::RaftStateMachine` and `RaftLogStorage` for `rusqlite` backends. | **COMPLETE** |
| **W7.2** | **RPC Handler Integration** | Wire `/raft` POST endpoint in `MeshProxy` to route messages to the internal `Raft` instance. | **COMPLETE** |
| **W7.3** | **Cluster Lifecycle & Init** | Implement Global node bootstrap, join logic, and leadership monitoring. | **COMPLETE** |
| **W7.4** | **Client Write Correction** | Update `RaftAwareClient` to use `client_write` (Proposals) instead of raw `AppendEntries`. | **COMPLETE** |
| **W7.5** | **SQLite Snapshots** | Implement point-in-time snapshotting using SQLite's backup API for log compaction. | **COMPLETE** |

### W7.1: Storage Layer Traits (COMPLETE)
- Implemented `GlobalRegistryTypeConfig` for `GlobalRegistry` types
- `RaftLogReader` for log entry reading with rusqlite
- `RaftLogStorage` with append, truncate_after, purge methods
- `RaftSnapshotBuilder` for state machine snapshotting
- `RaftStateMachine` with apply, install_snapshot, get_current_snapshot
- Uses `#[add_async_trait]` macro from openraft_macros

### W7.2: RPC Handler Integration (COMPLETE)
- Added `/raft` POST endpoint handler in MeshTransport via RaftInstance
- Added `ClientProposal` to `RaftMsgType` for client write operations
- `handle_raft_message()` routes Raft RPCs to `RaftInstance.client_write()`
- `MeshMessage::Raft` variant properly deserialized and dispatched

### W7.3: Cluster Lifecycle & Init (COMPLETE)
- Created `RaftInstance` struct wrapping `openraft::Raft`
- `initialize()` method for cluster bootstrap with nodes
- `wait_for_leader()` for leadership detection
- Node management methods (add_node, remove_node)
- Leadership monitoring via `is_leader()` and `get_leader_id()`

### W7.4: Client Write Correction (COMPLETE)
- `RaftAwareClient` now uses `client_write()` instead of raw `AppendEntries`
- Added `raft_write_local()` and `raft_write_via_global()` methods
- `set_raft_instance()` for Edge/Origin nodes to access Global Raft
- `ClientProposal` variant added to `RaftMsgType` enum

### W7.5: SQLite Snapshots (COMPLETE)
- `RaftSnapshotManager` using rusqlite backup API
- `create_point_in_time_snapshot()` for log compaction
- `restore_from_snapshot()` for recovery
- `compact_database()` using VACUUM
- `get_snapshot_path()` for snapshot file management

---

## Completed: Wave 6 - Mesh Consensus Foundations

| # | Task | Description | Status |
|---|------|-------------|--------|
| **W6.1** | **Raft Foundation** | Integrate `openraft` into the Global Node tier via MeshMessage::Raft variant. | **COMPLETE** |
| **W6.2** | **Raft State Machine & Registry** | Implement the `GlobalRegistry` state machine for `OrgPublicKey` and `ThreatIntel`. | **COMPLETE** |
| **W6.3** | **Raft-Aware Client** | Implement ConsistentRead RPC for Edge/Origin nodes with DHT fallback. | **COMPLETE** |
| **W6.4** | **Consensus-Driven Trust Transition** | Transition from 2/3 signature hunting to Raft-commitment as authority. | **COMPLETE** |

### W6.1: Raft Foundation (COMPLETE)
- Integrated `openraft = "0.10.0-alpha.18"` with serde feature
- Created `src/mesh/raft/network.rs` - MeshRaftNetwork and MeshRaftNetworkFactory
- Implements `RaftNetworkV2` trait wrapping MeshBackendPool
- `MeshMessage::Raft` variant with `RaftPayload` and `RaftMsgType` enum
- Raft RPCs multiplexed over existing QUIC mesh via /raft endpoint

### W6.2: Global Registry State Machine (COMPLETE)
- Created `src/mesh/raft/state_machine.rs`
- `GlobalRegistryStateMachine` - RaftStateMachine impl using rusqlite
- `GlobalRegistryLogStorage` - RaftLogStorage impl for log persistence
- Namespace enum: `Org`, `Intel`, `Revocation`
- Thread-safe implementations with `Arc<Mutex<Connection>>`

### W6.3: Raft-Aware Client (COMPLETE)
- Created `src/mesh/raft/client.rs` with `RaftAwareClient`
- `ConsistentReadRequest/Response` messages for strong reads
- Edge/Origin nodes query any Global node with leader hint mechanism
- DHT fallback when Raft is unreachable (marked as "Eventually Consistent")

### W6.4: Consensus-Driven Trust Transition (COMPLETE)
- Added `RaftCommitNotification` for leader commit broadcasting
- Updated `OrgKeyManager` with `commit_key_to_raft()` method
- `peer_auth.rs` now accepts either 2/3 quorum signatures OR Raft attestation
- Raft commit IS the cryptographic proof of majority consensus

---

## Completed: Wave 5 - OS Foundations & Core Optimization

| # | Task | Description | Status |
|---|------|-------------|--------|
| **W5.1** | **Windows Sandboxing** | Implement Job Objects and Process Mitigation Policies for OS-level confinement on Windows. | **COMPLETE** |
| **W5.2** | **macOS Sandboxing** | Implement `Sandbox.kext` (Scheme-based profiles) for macOS parity. | **COMPLETE** |
| **W5.3** | **Lock-Free BufferPool** | Replace sharded Mutexes with Thread-Local caches and Global Lock-Free Shards (Treiber stacks). | **COMPLETE** |

### W5.1: Windows Sandboxing (COMPLETE)
- Implemented `WindowsSandbox` using Windows Job Objects
- `CreateJobObjectW` for memory limits (256MB process, 512MB job)
- `KillOnJobClose` for automatic cleanup on parent exit
- DEP and ASLR mitigation policies via `SetProcessMitigationPolicy`
- `AssignProcessToJobObject` to apply sandbox to current process

### W5.2: macOS Sandboxing (COMPLETE)
- Implemented `SeatbeltSandbox` using macOS sandbox_init
- Dynamic Scheme profile generation based on `SandboxPaths`
- Basic mode: deny default, allow file-read* for allowed paths
- Strict mode: deny default, allow process/signal/job-creation only
- Requires `macos-sandbox` feature for actual enforcement

### W5.3: Lock-Free BufferPool (COMPLETE)
- `TreiberStack`: Lock-free stack using compare-and-swap
- `ThreadLocalCache`: 16 buffers per tier, zero atomic overhead in common case
- `TierArena`: Per-tier arena wrapping TreiberStack
- Hot path: `acquire` checks TLS cache first; `release` pushes to TLS first
- Backward compatible API - all 26 existing tests pass

---

## Recently Completed Items

| # | Issue | Fix | Date |
|---|-------|-----|------|
| P1.8 | `proxy_cache` not wired in `MeshProxy::route_request()` | Wired cache lookup/insert in `proxy_to_peer_with_fallback()` at `src/mesh/proxy.rs:1169-1259`. Added cache key builder, `is_cacheable_method`, `should_bypass_cache`, `is_response_cacheable`, `get_cache_max_age` helpers. | 2026-04-28 |
| P11.1 | Spin WASM HTTP routing not integrated | Added `BackendType::Spin` to router.rs, `spin_app_name` to RouteTarget, `BackendConfig::Spin` to config/site/backend.rs, and HTTP dispatch in server.rs at lines 1961-2048. | 2026-04-28 |
| P7A | WireGuard mesh transport enum not fully removed | Removed deprecated `WireGuard` variant from `MeshTransportPreference` in `src/mesh/config.rs:616-620`. Cleaned up `src/mesh/backend.rs:354-357` and `src/mesh/protocol.rs:1181-1185`. | 2026-04-28 |
| T1 | Threat Feed Production CLI | Implemented `ThreatIntelligenceManager::create_signed_feed()` and `--export-threat-feed` CLI command with Ed25519 key loading support. | 2026-04-29 |
| D1 | dashmap 5.5.3 → 7.0.0-rc2 | Updated version in Cargo.toml. Verified compilation. | 2026-04-28 |
| W1.1 | Strategic metrics module split | Split `src/metrics/mod.rs` into `src/metrics/payloads.rs` (structs) and `src/metrics/collection.rs` (atomic counters). Re-exports maintained for public API compatibility. | 2026-04-28 |
| W1.2 | Continuous fuzzing integration | Added `fuzz/fuzz_early_parse.rs` and `fuzz/fuzz_protocol_proto_decode.rs` targets to fuzz/Cargo.toml. | 2026-04-28 |
| W1.3 | E2E fault injection test | Added test simulating worker crash mid-request in `tests/integration_test.rs` for Overseer recovery verification. | 2026-04-28 |
| W2.1 | Zero-copy HTTP proxying | Implemented streaming body pipe for large responses (>1MB) in `src/http/server.rs` to reduce allocations at 500K RPS. | 2026-04-28 |
| W2.2 | HTTP/3 zero-copy proxying | Applied streaming body optimization to QUIC proxy paths in `src/http3/server.rs`. | 2026-04-28 |
| W2.3 | DHT routing LRU cache | Added moka-based LRU cache to `RoutingTable::find_closest` for O(1) hot path lookups. | 2026-04-28 |
| W2.4 | QUIC stream pooling | Implemented `StreamPool` in `src/tunnel/quic/client.rs` to reuse streams per peer instead of opening/closing per message. | 2026-04-28 |
| W3.1 | Site isolation audit | Audited `ratelimit.rs`, `rule_feed.rs`, and `WorkerMetrics` - found already properly isolated per site. | 2026-04-28 |
| W3.2 | WASM Component Model support | Created `src/plugin/plugin.wit` WIT file, added `load_component` implementation using wasmtime Component API. | 2026-04-28 |
| W4.1 | Automated threat feed ingestion | Created `src/waf/threat_intel/feed_client.rs` with Ed25519 signature verification and background fetch task. | 2026-04-28 |
| W4.2 | Threat feed DHT distribution | Added `ThreatFeedUpdate` IPC message, `broadcast_threat_feed_update`, and `publish_feed_indicator_to_dht` using SiteScoped keys. | 2026-04-28 |
| W6.1 | Raft Foundation | Integrated openraft with MeshMessage::Raft variant. Created MeshRaftNetwork/Factory. | 2026-04-29 |
| W6.2 | Raft State Machine | Implemented GlobalRegistryStateMachine and GlobalRegistryLogStorage with rusqlite. | 2026-04-29 |
| W6.3 | Raft-Aware Client | Created RaftAwareClient with ConsistentRead RPC and DHT fallback. | 2026-04-29 |
| W6.4 | Trust Transition | Added RaftCommitNotification, updated OrgKeyManager and peer_auth for dual verification. | 2026-04-29 |
| W7.1 | Storage Layer Traits | Implemented RaftStateMachine and RaftLogStorage with GlobalRegistryTypeConfig. All storage traits use rusqlite backend. | 2026-04-29 |
| W7.2 | RPC Handler Integration | Added /raft endpoint, ClientProposal to RaftMsgType, handle_raft_message() in MeshTransport. | 2026-04-29 |
| W7.3 | Cluster Lifecycle | Created RaftInstance wrapping openraft::Raft with initialize(), wait_for_leader(), add_node(), remove_node(). | 2026-04-29 |
| W7.4 | Client Write Correction | RaftAwareClient now uses client_write() instead of AppendEntries. Added raft_write_local(), raft_write_via_global(). | 2026-04-29 |
| W7.5 | SQLite Snapshots | RaftSnapshotManager with point-in-time snapshots using backup API, VACUUM compaction. | 2026-04-29 |

---

## Deferred Items

These items are intentionally deferred and do not block the current release:

| # | Issue | Reason |
|---|-------|--------|
| D7 | God module splits | Skipped: module splits of 10k+ lines introduce too much regression risk for automated agents; keeping intact to ensure no capability reversions |

---

## Recently Fixed Items

| # | Issue | Fix | Date |
|---|-------|-----|------|
| D11 | DNS TSIG timing side channel | Replaced XOR loop with `subtle::ConstantTimeEq::ct_eq()` at `src/dns/tsig.rs:237-240` | 2026-04-28 |

---

## Removed Items (Verified False/Invalid)

| # | Original Claim | Resolution |
|---|----------------|------------|
| ~~P0.10~~ | Rate Limit Bypass via WASM Filters | **REMOVED**: Wrong file references. Actual execution order (rate limit → WASM) is correct. WASM-blocked requests consuming rate limit quota is intended DDoS protection behavior. |
| ~~P0.11~~ | AxumDynamic WAF Bypass | **REMOVED**: False claim. AxumDynamic dispatch is inside the `WafDecision::Pass` branch — WAF checks ARE applied. |

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong for mesh/DHT keys
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary; JSON only for admin API
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`
- **WireGuard**: MESH transport deprecated/non-functional (slated for removal in P7A). VPN tunnel (`src/tunnel/wireguard/`) is separate and working.

---

## Verification Commands

```bash
# Verify tests compile (cargo check does NOT compile test code)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Feature-specific checks
cargo check --features dns
cargo check --features post-quantum
```

---

## Historical Context

All waves 1-7 were implemented and verified between 2026-04-27 and 2026-04-29. The full history of completed items is maintained in AGENTS.md under "Recently Completed Items."

---

## Future Work

All planned waves (1-7) are complete. For future enhancements, see `plans/future_work.md`.
