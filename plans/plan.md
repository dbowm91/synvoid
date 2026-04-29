# MaluWAF Implementation Plan

**Status**: Wave 1-5 Complete | Wave 6 In Progress
**Last Updated**: 2026-04-29
**Verification Completed**: 2026-04-29 (Wave 5)

---

## Overview

All implementation waves (1-5) are **COMPLETE**.
**Wave 6: Mesh Consensus & Trust Resiliency** is the current focus. It aims to incrementally migrate the global control plane from a complex Kademlia DHT to a more robust, Raft-based consensus model, while preserving existing, optimized mesh transports and avoiding immediate, disruptive replacement of the DHT.

**Wave 1-6 Implementation Summary:**
- Wave 1: Codebase Health & Testing Foundations (W1.1-W1.3)
- Wave 2: Performance & Scalability (W2.1-W2.4)
- Wave 3: Multi-Tenancy & Plugins (W3.1-W3.2)
- Wave 4: Security & Resilience (W4.1-W4.2)
- Wave 5: OS Foundations & Core Optimization (W5.1-W5.3)
- **Wave 6: Mesh Consensus & Trust Resiliency (W6.1-W6.4) [PLANNING]**

---

## Active Plan: Wave 6 - Mesh Consensus & Trust Resiliency

**Goal:** Incremental migration of the Global Control Plane from Kademlia DHT (eventual consistency) to Raft (strong consistency) to eliminate quorum deadlocks and simplify state management.

| # | Task | Description | Status |
|---|------|-------------|--------|
| **W6.1** | **Raft Foundation (Parallel to DHT)** | Integrate `openraft` into the Global Node tier. Map Raft RPCs to existing PQC-secured QUIC mesh transports. | Planned |
| **W6.2** | **Raft State Machine & Registry** | Implement the `GlobalRegistry` state machine for `OrgPublicKey` and `ThreatIntel`. | Planned |
| **W6.3** | **Raft-Aware Client (Edge/Origin)** | Update non-Global nodes to query the Raft cluster for authoritative state. | Planned |
| **W6.4** | **Consensus-Driven Trust Transition** | Transition from manual signature-hunting to Raft-commitment as the root of authority. | Planned |

### W6.1: Raft Foundation & Transport Mapping
- **Logic:** `openraft` requires a `RaftNetwork` implementation. Instead of a new port, we will multiplex Raft RPCs (AppendEntries, Vote, InstallSnapshot) over the existing `MeshMessage` protocol using a new `MeshMessage::Raft(RaftPayload)` variant.
- **Context:** This preserves our investment in **ML-KEM-768 key exchange** and **Hybrid Ed25519+ML-DSA signatures**, as all Raft traffic will inherit these security properties automatically.
- **Implementation:** Create `src/mesh/raft/network.rs` to wrap the `MeshBackendPool`.

### W6.2: The Global Registry State Machine
- **Logic:** The Raft state machine is a versioned key-value store where keys are structured as `(Namespace, ID)`. 
- **Records:**
  - `Namespace::Org`: Stores `OrgPublicKey`.
  - `Namespace::Intel`: Stores signed threat indicators.
  - `Namespace::Revocation`: Stores the `GlobalNodeRevocationList`.
- **Storage:** Use `rusqlite` for the `RaftStorage` implementation (`src/mesh/raft/storage.rs`) to ensure the log and state machine survive process restarts (Master/Overseer lifecycle).

### W6.3: Raft-Aware Clients (The "Observer" Role)
- **Logic:** Edge and Origin nodes do **not** participate in the Raft consensus (they are not voters). However, they need "Strong Read" capabilities.
- **Mechanism:** Implement a `ConsistentRead` RPC. An Edge node sends a query to any Global node; if that node is the Leader, it returns the value; if it's a Follower, it proxies to the Leader or returns a `NotLeader(LeaderId)` hint.
- **Fallback:** If Raft is unreachable, nodes MUST fallback to the DHT, but marked as "Eventually Consistent/Potentially Stale."

### W6.4: Quorum Deadlock & Trust Transition
- **The Problem:** The current system requires 2/3 of Global nodes to manually sign a record and publish it to the DHT. If 1/3+1 nodes are partitioned, no new trust records can be created.
- **The Solution:** In Raft, a record is "Authorized" the moment it is committed to the log. The Leader's commitment *is* the cryptographic proof of majority consensus.
- **Transition Logic:**
  1.  `OrgKeyManager` attempts to commit a new key to Raft.
  2.  Once committed, the Leader broadcasts a `RaftCommitNotification` via the DHT (gossip) to notify nodes that a new authoritative record exists.
  3.  Verification logic in `src/mesh/peer_auth.rs` is updated to accept **either** a 2/3 signature set (legacy) **or** a Raft-signed attestation from the current Leader.

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

All waves 1-4 were implemented and verified between 2026-04-27 and 2026-04-28. The full history of completed items is maintained in AGENTS.md under "Recently Completed Items."
