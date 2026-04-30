# AGENTS.md - Developer Guide for AI Agents

This document provides guidance for AI agents working on the MaluWAF codebase.

## Project Overview

MaluWAF is a WAF (Web Application Firewall) with a multi-process architecture:
- **Overseer** (`src/overseer/`): Manages master process lifecycle, upgrades, health monitoring
- **Master** (`src/master/`): Parent process that spawns/manages workers, handles IPC
- **Worker** (`src/worker/`): Handles HTTP requests and communicates via IPC

### Scalability Target

MaluWAF is designed for **high scalability** with targets well in excess of **500K requests/second**.

This has several implications:
- **Every allocation matters**: At 500K rps, even small per-request allocations compound to millions/sec
- **Avoid O(n) operations in hot paths**: Linear searches, repeated string conversions, unnecessary clones
- **Prefer O(1) lookups**: HashMap/HashSet over Vec iteration for any frequency
- **Reuse buffers**: Thread-local buffers, object pools, moka caches instead of per-request allocations
- **Lazy evaluation**: Only compute what's needed; defer expensive operations until confirmed necessary

When modifying hot path code, consider the multiplicative effect at scale:
```rust
// At 500K rps, these compound quickly:
// - 1 extra allocation/req × 500K = 500K allocations/sec
// - 8 extra allocations/req × 500K = 4M allocations/sec
// - Each extra CPU cycle × 500K = significant overhead
```

### Hot Path Locations

The following code paths execute on every request and must be optimized:
- `src/waf/attack_detection/` — WAF rule matching (runs per-request on all inputs)
- `src/mesh/proxy.rs` — Mesh proxy routing, caching, provider selection
- `src/http/server.rs` — HTTP request handling and dispatch
- `src/http3/server.rs` — HTTP/3 QUIC request handling and proxying
- `src/proxy/mod.rs` — Upstream proxy, cookie/cache key construction
- `src/plugin/wasm_runtime.rs` — WASM plugin filter/transform per request

### Serialization and Timestamp Patterns

For distributed state (DHT, Mesh messages, Persistence), follow these standards:

1. **Prefer Postcard over JSON**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary stability and performance. Avoid `serde_json` in high-performance or distributed paths.
2. **Use Typed Structs**: Do not use `serde_json::Value` (maps) for records. Define explicit Rust structs with `Archive`, `RkyvSerialize`, `RkyvDeserialize`, `Serialize`, and `Deserialize` derives.
3. **Unix Timestamps (u64)**: Use `u64` for all timestamps that need to be persisted or sent over the network. `Instant` is monotonic and local to a single process; it cannot be serialized or compared across reloads.
   - Use `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()` to get the current time.
   - Use `.saturating_sub()` for duration calculations.
4. **Binary Signatures**: Cryptographic signatures (Ed25519) should operate on `&[u8]`. Use `MeshMessageSigner::sign/verify` with binary data. Use `postcard` to generate stable signable bytes for structs.
5. **Base64 Encoding**: Always use `URL_SAFE_NO_PAD` for mesh/DHT data. `get_public_key()` at `src/mesh/protocol.rs:145` returns `URL_SAFE_NO_PAD`. Never use `STANDARD` decoder for keys synced via DHT.

Example of stable signable content:
```rust
pub fn get_signable_content(&self) -> Vec<u8> {
    #[derive(Serialize)]
    struct Signable<'a> {
        key: &'a str,
        value: &'a [u8],
        timestamp: u64,
    }
    crate::serialization::serialize(&Signable { ... }).unwrap()
}
```

## Running Tests

### Quick Test Commands

```bash
# Run integration tests only (fast, ~5 seconds)
cargo test --test integration_test

# Run without DNS feature (default)
cargo test

# With specific feature
cargo test --features dns

# Verify tests compile WITHOUT running them (important: cargo check does NOT compile test code)
cargo test --lib --no-run
```

### Test Categories

| Category | Command | Expected Time |
|----------|---------|---------------|
| Integration Tests | `cargo test --test integration_test` | ~5s |
| DNS Recursive Tests | `cargo test --test dns_recursive_test` | ~1s |
| DHT Integration Tests | `cargo test --test dht_integration_test` | ~1s |
| DNS Server Tests | `cargo test --test dns_server_test` | ~1s |
| E2E Process Tests | `cargo test --test e2e_process_test` | ~1s |
| IPC Tests | `cargo test --test ipc_test` | ~1s |
| All Tests (no DNS) | `cargo test` | ~3-5 min |
| DNS Feature Tests | `cargo test --features dns` | Varies |
| Unit Tests Only | `cargo test --lib` | ~3 min |
| Benchmarks | `cargo test --bench bench_*` | Varies |

### Common Issues

**Test Timeouts**: Full test suite can take 3+ minutes. Use targeted tests during development.

**`cargo check` vs test compilation**: `cargo check` does NOT compile `#[cfg(test)]` code. Always run `cargo test --lib --no-run` to verify test code compiles. Visibility errors in cross-module test access will only surface during test compilation.

## Known File Path Corrections

When working with the codebase, note these verified correct file paths:

| Wrong Path | Correct Path | Notes |
|-----------|-------------|-------|
| `src/http/client.rs` | `src/http_client/mod.rs` | HTTP client module |
| `src/mesh/proxy.rs:1485` (edge_only) | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` | edge_only flag locations |

## Critical Security Patterns

### Trusted Signer Default Deny

When checking `trusted_signers`, always use deny-by-default for non-global nodes:

```rust
if !self.node_role.is_global() {
    if self.config.trusted_signers.is_empty() {
        tracing::warn!("No trusted signers configured - rejecting threat from non-global node");
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
    if !self.check_trusted_signer(source_node_id, signer_public_key) {
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
}
```

### Constant-Time Comparison for Sensitive Data

Always use `subtle::ConstantTimeEq` for comparing secrets, tokens, keys, MACs:

```rust
use subtle::ConstantTimeEq;

// BEFORE (timing attack vulnerable)
let mut diff = 0u8;
for (a, b) in computed.iter().zip(original.iter()) {
    diff |= a ^ b;
}
if diff == 0 { ... }

// AFTER (constant-time)
if bool::from(computed.ct_eq(&original)) { ... }
```

**Locations requiring constant-time comparison**:
- DNS TSIG MAC verification (`src/dns/tsig.rs`)
- DNS cookie MAC verification (`src/dns/cookie.rs`)
- CSRF token validation (`src/auth/mod.rs`)
- Session ID comparison (`src/admin/state.rs`)

### Edge Node PoW Authentication

Edge nodes must provide BOTH `pow_nonce` AND `pow_public_key`:

```rust
if let (Some(nonce), Some(pk)) = (pow_nonce, pow_public_key) {
    validate_edge_node_pow(pubkey, nonce)?;
} else {
    return Err("Edge node did not provide PoW nonce and public key - PoW is required");
}
```

### Genesis Key Default Deny

Empty `authorized_genesis_keys` should deny by default:

```rust
pub fn is_genesis_key_authorized(&self, genesis_public_key: &str) -> bool {
    if self.authorized_genesis_keys.is_empty() {
        tracing::warn!("No authorized genesis keys configured - rejecting genesis key authentication.");
        return false;  // Changed from true (secure default)
    }
    self.authorized_genesis_keys.iter().any(|k| k == genesis_public_key)
}
```

### Composite Role Validation

For composite roles (EDGE_ORIGIN, GLOBAL_EDGE), check BOTH roles BEFORE single-role checks:

```rust
if role.is_edge() && role.is_origin() {
    let edge_result = validate_edge_node(...);
    let origin_result = validate_origin_node(...);
}
```

### YARA Rule Trust Validation

YARA rules enforce deny-by-default for non-global nodes:

```rust
if !self.node_role.is_global()
    && !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    // reject
}
```

## DNS DNSSEC RFC 5011 Trust Anchor States

Keys transition through states: **Seen → Pending → Valid → Revoked → Removed → Missing**

Only keys that were **previously Valid** (`trust_point != 0`) can auto-restore via `observe_dnskey_at_root()`. Keys never Valid (`trust_point == 0`) must go through digest verification via `trust_anchor_check()`.

## File Permissions for Private Keys

Always set restrictive permissions on private key files:

```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;

let temp_path = path.with_extension("tmp");
fs::write(&temp_path, &key_data)?;
fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
fs::rename(&temp_path, path)?;
```

## Verification Commands

```bash
# Verify tests compile
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

## Architecture Notes

### Overseer/Master/Worker IPC

The overseer/master/worker architecture uses:
- Unix domain sockets for IPC
- `Message` enum in `src/process/ipc.rs` for communication
- `ProcessManager` for worker lifecycle
- Health checks via IPC heartbeat messages

### Mesh Backend Pool

`BackendType::Mesh` variant is dispatched in the HTTP server via `mesh_backend_pool`. Key files:
- `src/mesh/backend.rs:109-303` — `MeshBackend`/`MeshBackendPool`
- `src/mesh/proxy.rs` — `MeshProxy` for routing

### Node Roles

Node roles defined at `src/mesh/config.rs:23-33`: Global, Edge, Origin, plus composites (GLOBAL_EDGE, EDGE_ORIGIN, GLOBAL_ORIGIN, GLOBAL_EDGE_ORIGIN).

## Skills Reference

The `skills/` directory contains detailed documentation for various subsystems:

| Skill | Purpose |
|-------|---------|
| `security_patterns.md` | Critical security fixes, constant-time comparison, path traversal, XSS prevention |
| `streaming_waf.md` | Streaming WAF engine patterns |
| `dht_persistence.md` | DHT neighborhood persistence |
| `hybrid_post_quantum.md` | Post-quantum signature implementation |
| `spin_wasm.md` | Spin WASM runtime |
| `serverless_wasm.md` | Serverless WASM patterns |
| `malu_mesh.md` | Mesh networking patterns |
| `topology_visualizer.md` | Topology visualizer API |
| `behavioral_intel.md` | Behavioral intelligence |
| `performance_patterns.md` | Performance optimization patterns |
| `admin_api.md` | Admin API patterns |
| `dns_dnssec.md` | DNS and DNSSEC patterns |
| `wasm_components.md` | WASM component model patterns |
| `dht_scoping.md` | DHT site isolation and scoping patterns |
| `threat_feed_production.md` | Production and signing of threat intel feeds |
| `raft_consensus.md` | Raft consensus integration for global control plane |

## Recently Completed Items

| # | Issue | Fix | Date |
|---|-------|-----|------|
| P1.8 | `proxy_cache` not wired in `MeshProxy::route_request()` | Wired cache lookup/insert in `proxy_to_peer_with_fallback()` at `src/mesh/proxy.rs:1169-1259`. Added cache key builder, `is_cacheable_method`, `should_bypass_cache`, `is_response_cacheable`, `get_cache_max_age` helpers. | 2026-04-28 |
| P11.1 | Spin WASM HTTP routing not integrated | Added `BackendType::Spin` to router.rs, `spin_app_name` to RouteTarget, `BackendConfig::Spin` to config/site/backend.rs, and HTTP dispatch in server.rs at lines 1961-2048. | 2026-04-28 |
| P7A | WireGuard mesh transport enum not fully removed | Removed deprecated `WireGuard` variant from `MeshTransportPreference` in `src/mesh/config.rs:616-620`. Cleaned up `src/mesh/backend.rs:354-357` and `src/mesh/protocol.rs:1181-1185`. | 2026-04-28 |
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
| W5.1 | Windows Sandboxing | Implemented `WindowsSandbox` using Windows Job Objects with memory limits (256MB process, 512MB job), KillOnJobClose, and DEP/ASLR mitigation policies via `src/platform/sandbox.rs:610-785`. | 2026-04-29 |
| W5.2 | macOS Sandboxing | Implemented `SeatbeltSandbox` using macOS sandbox_init with dynamic Scheme profile generation. Basic/Strict modes supported. Enable `macos-sandbox` feature for actual enforcement. | 2026-04-29 |
| W5.3 | Lock-Free BufferPool | Replaced `parking_lot::Mutex<VecDeque>` with Thread-Local Cache (16 buffers/tier) and Treiber Stack (lock-free). Hot path acquire checks TLS first, release pushes to TLS first. All 26 tests pass. | 2026-04-29 |
| T1 | Threat Feed Production CLI | Implemented `ThreatIntelligenceManager::create_signed_feed()` for producing signed feeds, and `--export-threat-feed` CLI command with Ed25519 key loading (file, genesis, or config). Unit tests verify signable content format matches `ThreatFeedClient`. | 2026-04-29 |
| W6.1 | Raft Foundation | Integrated openraft with MeshMessage::Raft variant. Created MeshRaftNetwork/Factory wrapping MeshBackendPool. | 2026-04-29 |
| W6.2 | Raft State Machine | Implemented GlobalRegistryStateMachine and GlobalRegistryLogStorage with rusqlite persistence. Namespace: Org, Intel, Revocation. | 2026-04-29 |
| W6.3 | Raft-Aware Client | Created RaftAwareClient with ConsistentRead RPC for Edge/Origin nodes. DHT fallback when Raft unreachable. | 2026-04-29 |
| W6.4 | Trust Transition | Added RaftCommitNotification. Updated OrgKeyManager and peer_auth to accept either 2/3 signatures OR Raft attestation. | 2026-04-29 |
| W7.1 | Storage Layer Traits | Implemented GlobalRegistryTypeConfig, RaftStateMachine, RaftLogStorage, RaftLogReader, RaftSnapshotBuilder with rusqlite. Uses #[add_async_trait] macro. | 2026-04-29 |
| W7.2 | RPC Handler Integration | Added /raft endpoint via RaftInstance, ClientProposal to RaftMsgType, handle_raft_message() in MeshTransport. | 2026-04-29 |
| W7.3 | Cluster Lifecycle | Created RaftInstance wrapping openraft::Raft with initialize(), wait_for_leader(), add_node(), remove_node() methods. | 2026-04-29 |
| W7.4 | Client Write Correction | RaftAwareClient uses client_write() instead of AppendEntries. Added raft_write_local(), raft_write_via_global(), set_raft_instance(). | 2026-04-29 |
| W7.5 | SQLite Snapshots | RaftSnapshotManager with point-in-time snapshots using rusqlite backup API, VACUUM compaction, get_snapshot_path(). | 2026-04-29 |
| W8.1 | Raft-Backed CRL | OrgKeyManager::revoke_global_node() commits to Namespace::Revocation via Raft. Falls back to DHT when Raft unavailable. Broadcasts RaftCommitNotification. | 2026-04-30 |
| W8.2 | Observer Nodes | Added is_observer and observer_tags to RaftInitConfig/RaftInstance. RaftInstance::add_learner() using openraft API. Observers use add_learner(node_id, (), false). | 2026-04-30 |
| W8.3 | Genesis Membership | RaftInstance::change_membership() wrapping openraft API. PendingMembershipChange queue for non-leader scenarios. Auto-add via handle_global_node_announce. | 2026-04-30 |
| W8.4 | Edge State Mirroring | EdgeReplicaManager in src/mesh/raft/edge_replica.rs with moka cache (10K, 5-min TTL). get_org_key(), get_threat_intel() for O(1) lookups. RaftAwareClient::query_leader_for_record(). | 2026-04-30 |
| W8.5 | YARA-X Modernization | Verified complete: codebase exclusively uses yara-x v1.15+. No libyara C dependencies. yara_x::compile(), Scanner, Rules used throughout. | 2026-04-30 |

## Known Issues

There are no known incomplete items. All items from `plans/plan.md` have been verified and completed (or explicitly skipped where appropriate):

- **D7 God module splits**: Skipped due to "no capability reversions" requirement
- All W1.x through W8.x items: Verified and implemented

## Architecture Notes

### Overseer/Master/Worker IPC

The overseer/master/worker architecture uses:
- Unix domain sockets for IPC
- `Message` enum in `src/process/ipc.rs` for communication
- `ProcessManager` for worker lifecycle
- Health checks via IPC heartbeat messages

### Mesh Backend Pool

`BackendType::Mesh` variant is dispatched in the HTTP server via `mesh_backend_pool`. Key files:
- `src/mesh/backend.rs:109-303` — `MeshBackend`/`MeshBackendPool`
- `src/mesh/proxy.rs` — `MeshProxy` for routing

### Node Roles

Node roles defined at `src/mesh/config.rs:23-33`: Global, Edge, Origin, plus composites (GLOBAL_EDGE, EDGE_ORIGIN, GLOBAL_ORIGIN, GLOBAL_EDGE_ORIGIN).

### Raft Consensus (Wave 6-7)

Global nodes form a Raft cluster for strong consistency. Key files:
- `src/mesh/raft/mod.rs` — Raft module exports
- `src/mesh/raft/network.rs` — MeshRaftNetwork and MeshRaftNetworkFactory
- `src/mesh/raft/state_machine.rs` — GlobalRegistryStateMachine and GlobalRegistryLogStorage (with full RaftStateMachine/RaftLogStorage traits)
- `src/mesh/raft/client.rs` — RaftAwareClient for ConsistentRead RPC
- `src/mesh/raft/instance.rs` — RaftInstance wrapping openraft::Raft with client_write(), initialize(), wait_for_leader()
