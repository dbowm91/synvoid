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

## Dependency Policy

### Rust-First Dependency Policy

We prefer **pure Rust dependencies** over those with C bindings where possible. When selecting dependencies, consider:

1. **Prefer pure Rust**: Libraries like `libinjectionrs` (SQL injection detection) and `bcrypt` (password hashing) are pure Rust implementations
2. **Well-audited and maintained**: Ensure any C-binding library is battle-tested and actively maintained
3. **No acceptable alternative**: Some dependencies are simply required (see exceptions below)

### Known Exceptions (Required)

| Dependency | Purpose | Why Acceptable |
|------------|---------|----------------|
| **aws-lc-rs** | TLS/crypto | Amazon's Rust crypto (Ring successor), battle-tested, no pure Rust alternative for post-quantum TLS |
| **libc** | Unix syscalls | Thin Rust bindings to kernel - no alternative exists |
| **windows-sys** | Windows API | Thin Rust bindings to Win32 API - no alternative exists |

### Confirmed Pure Rust Libraries

| Library | Purpose | Verification |
|---------|---------|--------------|
| `libinjectionrs` | SQL/XSS injection detection | 100% Rust port, no FFI |
| `bcrypt` | Password hashing | Uses `blowfish` crate (pure Rust), `#![forbid(unsafe_code)]` |

### Adding New Dependencies

When adding dependencies:
- Verify the crate is pure Rust (check for `build.rs` with C compilation, `extern` declarations, or FFI)
- Check cargo registry for `unsafe_code` warnings
- Prefer crates with `forbid(unsafe_code)` or clear `unsafe` boundaries
- Document any exceptions in this file

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
cargo clippy --lib -- -D warnings

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

### Raft Consensus

Global nodes form a Raft cluster for strong consistency. Key files:
- `src/mesh/raft/mod.rs` — Raft module exports
- `src/mesh/raft/network.rs` — MeshRaftNetwork and MeshRaftNetworkFactory with full_snapshot() support
- `src/mesh/raft/state_machine.rs` — GlobalRegistryStateMachine, GlobalRegistryLogStorage, GlobalRegistrySnapshotBuilder
- `src/mesh/raft/client.rs` — RaftAwareClient with LeaderCache (5s TTL), linearizable reads, DHT fallback
- `src/mesh/raft/instance.rs` — RaftInstance wrapping openraft::Raft
- `src/mesh/raft/regression_tests.rs` — Regression tests for Raft messages and DHT signatures

**Namespaces**: Org, Intel, Revocation (defined in `state_machine.rs`)

**DHT Fallback**: When Raft is unavailable, `RaftAwareClient::fallback_to_dht()` provides eventual consistency via DHT lookups.

**Streaming Snapshots (W11.2)**: Raft snapshots use a streaming binary format to avoid OOM on large state. Key methods:
- `GlobalRegistryStateMachine::streaming_serialize()` — iterates SQLite rows, serializes one entry at a time
- `GlobalRegistryStateMachine::streaming_deserialize_and_apply()` — deserializes and inserts one entry at a time
- Format: `[MAGIC u32 0x53524D53][COUNT u64][LEN u32][postcard entry]...`
- Backward-compatible: falls back to JSON deserialization if magic number is absent (rolling upgrades)
- Peak memory reduced from ~2x state size to ~1x state size

### Raft Command Authorization

`RaftCommand` variants (`Set`, `Delete`) include `source_node_id` and `signature` fields (Optional) to support authorization validation at the handler level before accepting proposals.

### DHT Security

DHT record signing uses canonical `DhtRecordSignable` struct with SHA256 value hashing:
- `src/mesh/dht/signed.rs` — SignedDhtRecord, DhtRecordSignable, RecordSigner/Verifier
- `src/mesh/transport_dht.rs` — handle_dht_snapshot_request/sync_response with default-deny authentication

**Default-Deny**: DHT snapshot/sync requests without valid signatures are rejected.

### DHT Record Versioning

Immutable record types cannot be replaced once stored:
- `GenesisKeyTransition` — Genesis key rotation records
- `RevokedGlobalNode` — Revocation records
- `YaraRulesManifest` — YARA rule manifests
- `YaraRuleContent` — YARA rule content

These use `SignedRecordType::is_immutable()` check in both `store_record_global()` and `apply_sync()`.

### DHT Timestamp Validation

All DHT records are validated against future timestamps using `validate_record_timestamp()` with `DHT_RECORD_TIMESTAMP_WINDOW_SECS` (300 seconds). Records with timestamps too far in the future are rejected before storage.

### DHT Regional Quorum (W11.1)

DHT quorum supports two modes via `QuorumMode`:
- **Full** (default): Requires 2/3+1 of ALL global nodes — doesn't scale beyond ~100 nodes.
- **Regional**: Selects closest N global nodes by latency, computes quorum from that subset only.

Key files:
- `src/mesh/dht/quorum.rs` — `QuorumMode`, `select_regional_nodes()`, `GlobalNodeInfo`
- `src/mesh/dht/record_store.rs` — `RecordStoreConfig` fields: `regional_quorum_enabled`, `regional_quorum_max_nodes`, `regional_quorum_min_nodes`
- `src/mesh/dht/record_store_message.rs` — `start_quorum_request()` uses regional mode when enabled

Configuration: Set `regional_quorum_enabled = true` in `RecordStoreConfig` with `regional_quorum_max_nodes` (default 20) and `regional_quorum_min_nodes` (default 3). Disabled by default for backward compatibility.

### DHT Two-Phase Commit (W11.3)

DHT records requiring quorum use a two-phase commit to prevent gossip of unconfirmed state:

1. **Phase 1 (Pending)**: Record is stored with `DhtRecordStatus::PendingQuorum` status immediately when `store_record_global()` is called. The record is hidden from `get_record()` and `get_all_records()` but exists locally.
2. **Phase 2 (Commit)**: When quorum approves, `commit_record_after_quorum()` transitions status to `Live`, queues for announce, and sends `DhtRecordCommit` to peers.

Key types:
- `DhtRecordStatus` enum (`PendingQuorum`, `Live`) in `src/mesh/protocol.rs`
- `DhtRecordCommit` message variant in `MeshMessage` for signaling commitment to peers
- `QuorumSignatureProto` for serializing quorum signatures in commit messages

Key methods:
- `store_record_global()` — stores quorum-requiring records as `PendingQuorum` before starting quorum request
- `commit_record_after_quorum()` — transitions to `Live`, announces, sends `DhtRecordCommit` to peers
- `abort_pending_record()` — removes record on rejection/timeout
- `get_record()` / `get_all_records()` — filter out `PendingQuorum` records
- `handle_record_commit()` — handles incoming `DhtRecordCommit` messages on receiving nodes

All 84 `mesh::dht` tests pass with this implementation.

### Async PQC Verification Pool (W11.4)

CPU-intensive PQC operations (ML-DSA verification, ML-KEM encapsulation/decapsulation) can offload to a blocking thread pool to avoid blocking the async executor:

Key file: `src/mesh/crypto_verification.rs` — `CryptoVerificationPool`

```rust
use crate::mesh::CryptoVerificationPool;

let pool = CryptoVerificationPool::default_pool();

// Async ML-DSA verification
let result = pool.verify_ml_dsa(&vk_bytes, message, &signature).await;

// With Arc<MeshMlDsaSigner>
let result = pool.verify_ml_dsa_with_signer(signer_arc, message, &signature).await;

// Async ML-KEM operations
let (ct, ss) = pool.ml_kem_encapsulate(&pk_bytes).await?;
let ss = pool.ml_kem_decapsulate(&sk_bytes, &ct).await?;
```

Pool characteristics:
- Uses `tokio::task::spawn_blocking` for CPU-intensive crypto
- Default size: `available_parallelism().max(4)` threads
- Non-blocking async interface over blocking crypto operations
- Available for integration with `MeshMessageSigner::verify_hybrid()` when ML-DSA is used in hot paths

### DHT Disk-Backed Storage (W11.5)

`ShardedRecordStore` uses in-memory BTreeMap shards. For persistent storage across restarts, configure `disk_storage_path`:

Key files:
- `src/mesh/dht/record_store_disk.rs` — SQLite-backed `DiskRecordStore`
- `src/mesh/dht/record_store.rs` — `load_from_disk()`, `persist_to_disk()` methods

Configuration:
```rust
let store_config = RecordStoreConfig {
    disk_storage_path: Some("/path/to/dht.db".to_string()),
    ..Default::default()
};
```

Methods:
- `load_from_disk()` — Load all records from SQLite into in-memory store on startup
- `persist_to_disk()` — Persist all in-memory records to SQLite

SQLite schema uses WAL mode for concurrent read access. See `skills/dht_persistence.md` for full details.

### DHT L1/L2 Cache (W11.6)

`DiskRecordStore` acts as a transparent L2 cache layered over `ShardedRecordStore` L1 (in-memory):

Key files:
- `src/mesh/dht/record_store_crud.rs` — `get_record()`, `store_record_global()`
- `src/mesh/dht/record_store.rs` — `warmup_from_disk()`
- `src/mesh/dht/record_store_message.rs` — `commit_record_after_quorum()`, `abort_pending_record()`

L1 read-through: `get_record()` checks disk if record not in memory (global nodes only)
Write-through: `store_record_global()` writes to both L1 and L2
Quorum sync: `commit_record_after_quorum()` promotes to Live in both stores; `abort_pending_record()` removes from both

Startup: `warmup_from_disk()` rebuilds Merkle tree from disk keys without loading all values into RAM.

### Real-world Latency Tracking (W11.8)

Regional quorum now uses rolling average RTT instead of last measurement:

- `ShardedPeerStore::record_latency()` maintains last 20 RTT samples per node
- `update_peer_latency()` computes rolling average and updates `PeerState.latency_ms`
- `MeshTopology::get_average_latency_for_node()` exposes rolling average
- `start_quorum_request()` uses average latency for `select_regional_nodes()` when available

Key files:
- `src/mesh/topology/types.rs` — `ShardedPeerStore::update_peer_latency()`, `get_average_latency()`
- `src/mesh/topology.rs` — `MeshTopology::get_average_latency_for_node()`
- `src/mesh/dht/record_store_message.rs` — Regional node selection uses average latency

### Incremental Merkle Updates (W12.1)

`MerkleTree` uses level-ordered hash arrays for O(log N) point updates on existing keys. Key methods:
- `MerkleTree::insert_or_update(key, value)` — O(log N) if key exists, full rebuild for new keys
- `MerkleTree::remove_key(key)` — Removes key and rebuilds tree
- `RecordStoreManager::update_merkle_incremental(key, value)` — Updates tree for single record changes
- `RecordStoreManager::remove_merkle_key(key)` — Removes key from tree

Single-record paths use incremental updates; bulk operations (sync, snapshot, anti-entropy) retain full `compute_merkle_tree()`. A Merkle Integrity Worker runs hourly in `start_background_tasks` to detect and correct drift.

Key files:
- `src/mesh/dht/merkle.rs` — Level-based MerkleTree with incremental updates
- `src/mesh/dht/record_store_message.rs` — `update_merkle_incremental()`, integrity worker in `start_background_tasks()`
- `src/mesh/dht/record_store_crud.rs` — Uses incremental updates in `store_record_global()`, `store_record_edge_cache()`

### Cryptographically-Enforced Quorum Gossip (W12.2)

Records in sensitive namespaces (`verified_upstream:`, `tier_claim:`) require a `quorum_proof` to be accepted via gossip/sync/commit. This prevents a single compromised node from promoting a `PendingQuorum` record to `Live` without quorum approval.

Key concepts:
- `DhtRecord.quorum_proof: Vec<QuorumSignatureProto>` — Attached during `commit_record_after_quorum()`, propagated via `DhtRecordCommit` and sync
- `DhtAccessControl::requires_quorum_proof(key)` — Returns true for `verified_upstream:*` and `tier_claim:*`
- `signed::verify_quorum_proof(record, global_node_count)` — Checks distinct signer count >= 2/3+1 threshold (min 2)
- Passive confirmation (`PendingQuorum` → `Live` via gossip) is now quorum-proof-enforced for sensitive namespaces

Key files:
- `src/mesh/protocol.rs:1541` — `DhtRecord.quorum_proof` field
- `src/mesh/dht/signed.rs` — `verify_quorum_proof()`, `MIN_QUORUM_PROOF_SIGNATURES`
- `src/mesh/dht/record_store_crud.rs` — Quorum-proof enforcement in `store_record_global()` and `apply_sync()`
- `src/mesh/dht/record_store_message.rs` — `commit_record_after_quorum()` attaches proof, `handle_record_commit()` verifies it

## Known Issues

| Issue | Reason | Workaround |
|-------|--------|------------|
| **D7 God module splits** | Skipped due to "no capability reversions" requirement | Manual refactor needed if desired |

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
| `sandboxing.md` | OS sandboxing (Windows/macOS) |

## Future Work

For recommended future enhancements, see `plans/future_work.md`.