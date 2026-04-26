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

# Run with specific feature
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

**`cargo check` vs test compilation**: `cargo check` does NOT compile `#[cfg(test)]` code. Always run `cargo test --lib --no-run` to verify test code compiles. Visibility errors in cross-module test access (e.g., sibling modules calling private methods) will only surface during test compilation.

**Ignored tests**: Several tests are marked `#[ignore]` with explanations:
- `src/streaming/bidirectional.rs:337,365` — copy_bidirectional ring buffer deadlock (FIXED: use `copy_bidirectional_with_config`)
- `src/process/socket_fd.rs:626,648` — Require cross-process FD transfer (SCM_RIGHTS)
- DashMap test hang issue was fixed by using RwLock<HashMap> in SlidingWindowLimiter for test contexts

## Codebase Structure

### Key Modules

- `src/process/` - IPC communication, process management
- `src/overseer/` - Master process orchestration
- `src/master/` - Parent process implementation
- `src/worker/` - Worker process implementation
- `src/mesh/` - Mesh networking (proxy, transport, DHT, threat intel, YARA)
- `src/mesh/backend.rs` - `MeshBackend`/`MeshBackendPool` (health checking, pool selection)
- `src/waf/` - WAF engine (attack detection, rate limiting, bot protection)
- `src/plugin/` - WASM plugin runtime and instance pooling
- `src/serverless/` - Serverless function management
- `src/admin/` - Admin API (handlers, WebSocket, OpenAPI)
- `tests/` - Integration tests

### Admin API Documentation

The Admin API provides OpenAPI 3.0 documentation at these endpoints:

| Endpoint | Description |
|---------|-------------|
| `/api/openapi.json` | Raw OpenAPI 3.0 JSON spec |
| `/api/docs` | HTML page with links to external Swagger UI |

The API uses Bearer token authentication (add `Authorization: Bearer <token>` header).

### Architecture Pattern

The overseer/master/worker architecture uses:
- Unix domain sockets for IPC
- `Message` enum in `src/process/ipc.rs` (re-exported via `src/process/mod.rs`) for communication
- `ProcessManager` for worker lifecycle
- Health checks via IPC heartbeat messages

### Key Mesh Components

- `MeshBackend`/`MeshBackendPool` at `src/mesh/backend.rs:109-303` — backend health checking and selection. Wired to HTTP request handling via `BackendType::Mesh`.
- `MeshProxy` at `src/mesh/proxy.rs` — request routing, caching, provider selection
- `MeshTransport` at `src/mesh/transport.rs` — peer communication, transport initialization
- `DHT` at `src/mesh/dht/` — distributed hash table for state sync
- Node roles defined at `src/mesh/config.rs:23-33`: Global, Edge, Origin, plus composites (GLOBAL_EDGE, EDGE_ORIGIN, GLOBAL_ORIGIN, GLOBAL_EDGE_ORIGIN)
- `ReplayProtection` at `src/mesh/protocol.rs:153-196` — marked as `#[allow(dead_code)]` (was dead code, kept for potential future use)

## Adding Tests

### Integration Tests Location

Add tests to `tests/integration_test.rs` for architecture-level coverage:

```rust
#[test]
fn test_new_feature() {
    use maluwaf::module::Type;
    // Test implementation
}
```

### Unit Tests Location

Add `#[cfg(test)]` modules to source files:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_unit() {
        // Test implementation
    }
}
```

### IPC Socket Tests

When testing actual socket communication, use temporary directories:

```rust
use tempfile::TempDir;

#[test]
fn test_ipc_socket() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    // Test socket communication
}
```

## Lint and Format

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy -- -D warnings

# Check without building
cargo check
```

**`cargo fmt` prerequisites**: `src/platform/windows.rs` must exist (even as a stub) or `cargo fmt` will fail with "failed to resolve mod `windows`". The file exists as a stub gated by `#[cfg(windows)]`.

## Feature Flags

Key features that affect testing:
- `dns` - DNS server functionality (optional, conditionally compiled)
- `socket-handoff` - Socket transfer between processes
- `post-quantum` - Post-quantum cryptography
- Serverless functions use WASM (wasmtime), not Deno

**Note**: WireGuard transport is deprecated and non-functional — the system falls back to QUIC transport with a warning. Code still exists at `src/mesh/wireguard_mesh.rs`.

## Common Patterns

### Testing IPC Messages

```rust
use maluwaf::process::Message;

// Serialize/deserialize
let msg = Message::WorkerStarted { id: 1, pid: 12345, .. };
let json = serde_json::to_string(&msg).unwrap();
let decoded: Message = serde_json::from_str(&json).unwrap();
```

### Socket Handoff Message API

The socket handoff feature uses specific Message variants with these fields:

| Message Variant | Fields |
|----------------|--------|
| `SocketHandoffRequest` | `socket_path: String` |
| `SocketHandoffReady` | `ports: Vec<u16>` |
| `SocketHandoffComplete` | `success: bool`, `fd_count: usize` |
| `SocketHandoffFailed` | `error: String` |

Socket handoff tests require the `socket-handoff` feature.

### Testing Worker Lifecycle

```rust
use maluwaf::worker::drain_state::WorkerDrainState;

let state = WorkerDrainState::new();
state.start_drain(1);
assert!(state.is_draining());
```

### Testing Overseer Config

```rust
use maluwaf::overseer::process::OverseerConfig;

let config = OverseerConfig::default();
assert!(config.auto_restart);
```

### Testing Trust Anchor State Transitions

```rust
use maluwaf::dns::trust_anchor::{TrustAnchorManager, TrustAnchorConfig, Rfc5011Event};

let config = TrustAnchorConfig {
    pending_observation_days: 30,
    revocation_grace_days: 30,
    extended_removal_days: 60,
    trust_anchor_retention_days: 7,
    ..TrustAnchorConfig::default()
};
let manager = TrustAnchorManager::new(config);

let event = manager.observe_dnskey_at_root(key_tag, algorithm, &public_key, false);
assert!(matches!(event, Rfc5011Event::NewKeySeen { .. }));
```

### Dropped Event Metrics

Global counters for silently dropped channel send failures live in `src/metrics/mod.rs`. Pattern:

```rust
// 1. Add global static counter
static DROPPED_FOO_EVENTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

// 2. Add record/get functions
pub fn record_dropped_foo_event() {
    DROPPED_FOO_EVENTS.fetch_add(1, Ordering::Relaxed);
}
pub fn get_dropped_foo_events() -> u64 {
    DROPPED_FOO_EVENTS.load(Ordering::Relaxed)
}

// 3. Instrument call site
if sender.send(event).is_err() {
    crate::metrics::record_dropped_foo_event();
    tracing::warn!("Failed to send foo event");
}
```

Query via `get_dropped_event_counts() -> DroppedEventCounts` (per-category breakdown + total).

### Concurrency Patterns

- **DashMap** (170+ uses in codebase): Preferred over `RwLock<HashMap>` for hot paths. Use for any map accessed on every request.
- **Atomic types** (`AtomicU64`, `AtomicU32`, etc.): Use for scalar counters and state flags instead of `RwLock<T>` where T is a simple type.
- **Moka Cache**: Use for bounded caches with TTL. Configure both `max_capacity` and `time_to_live`.

## File Naming Conventions

- Source files: `snake_case.rs`
- Test files: `snake_case_test.rs` or in `tests/` directory
- Modules: `mod.rs` for module aggregation

## DNSSEC and RFC 5011

### Trust Anchor Configuration

| Field | Default | Purpose |
|-------|---------|---------|
| `pending_observation_days` | 30 | Time in Pending before Valid (RFC 5011 Section 3.2) |
| `revocation_grace_days` | 30 | Time before Removed (RFC 5011 Section 4) |
| `extended_removal_days` | 60 | Time before Purged from storage |
| `trust_anchor_retention_days` | 7 | Time Valid key absent before Missing |

### RFC 5011 State Machine

Keys transition: **Seen** → **Pending** → **Valid** → **Revoked** → **Removed** → **Missing**

**Missing→Pending restoration**: Only keys previously Valid (trust_point != 0) can auto-restore via `observe_dnskey_at_root()`. Others must go through `trust_anchor_check()` first.

## Important Notes

1. **Never commit secrets** - Use `.gitignore` for credentials
2. **Test isolation** - Use temp dirs for socket tests
3. **Async tests** - Use `#[tokio::test]` for async code
4. **Platform-specific tests** - Use `#[cfg(unix)]` or `#[cfg(windows)]`
5. **Key tag calculation** - Use `crate::dns::dnssec::calculate_key_tag` for RFC 4034 compliant key tags
6. **Base64 consistency** - Always `URL_SAFE_NO_PAD` for mesh/DHT, never `STANDARD`

### Startup Validation Patterns

The codebase uses placeholder values that should trigger warnings at startup:

| Placeholder | Location | Behavior |
|-----------|----------|----------|
| `DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER` | `src/waf/rule_feed.rs:321` | **Panics** on startup (fail-closed security behavior) |
| `TOKEN_PLACEHOLDER` | `src/config/admin.rs` | Detected as weak token |

These placeholders indicate the value was not configured and may indicate a security issue.

### Critical Security Patterns

**Trusted Signer Verification for ThreatAnnounce**
```rust
// In threat_intel.rs: After signature verification, check trusted_signers
if !self.node_role.is_global() && !self.config.trusted_signers.is_empty() {
    if !self.check_trusted_signer(source_node_id, signer_public_key) {
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
}
```

**Composite Role Validation (EDGE_ORIGIN, GLOBAL_EDGE)**
```rust
// In peer_auth.rs: Check composite roles BEFORE single-role checks
if role.is_edge() && role.is_origin() {
    // Require BOTH edge AND origin validation
    let edge_result = validate_edge_node(...);
    let origin_result = validate_origin_node(...);
}
```

**DNS Mesh Mode Enforcement**
```rust
// In dns/server/startup.rs: Skip DNS binding for non-global when enforced
if let Some(ref transport) = self.mesh_transport {
    let cfg = transport.get_mesh_config();
    if let Some(ref dht_cfg) = cfg.dht {
        if dht_cfg.dns_mesh_mode_only && !cfg.role.is_global() {
            return Ok(()); // Skip binding
        }
    }
}
```

**DHT Quorum Authorization**
```rust
// In record_store_message.rs: Verify signer is authorized global node
let authorized = cert_mgr.read().is_global_node_authorized(signer_pk);
if !authorized {
    return false; // Reject quorum contribution
}
```

**Edge Node PoW Authentication (REQUIRED)**
```rust
// Edge nodes must provide BOTH pow_nonce AND pow_public_key
// If either is missing, authentication fails with error
if let (Some(nonce), Some(pk)) = (pow_nonce, pow_public_key) {
    validate_edge_node_pow(pubkey, nonce)?;
} else {
    return Err("Edge node did not provide PoW nonce and public key - PoW is required");
}
```

**Genesis Key Default Deny**
```rust
// Empty authorized_genesis_keys now denies by default (security fix)
pub fn is_genesis_key_authorized(&self, genesis_public_key: &str) -> bool {
    if self.authorized_genesis_keys.is_empty() {
        tracing::warn!("No authorized genesis keys configured - rejecting genesis key authentication.");
        return false;  // Changed from true (secure default)
    }
    self.authorized_genesis_keys.iter().any(|k| k == genesis_public_key)
}
```

### Mesh Configuration Patterns

**Mesh Routing Configuration**
```toml
[mesh]
enabled = true

[mesh.proxy]
request_timeout_secs = 30
stale_cache_ttl_secs = 60
```

**Mesh Backend Pool Wiring**
- `BackendType::Mesh` variant added to router enum
- `mesh_backend_pool: Option<Arc<MeshBackendPool>>` field in UnifiedServer
- Use `site_config.mesh_routing` to enable mesh routing for a site

## Deferred Items

The following items are deferred and should not be attempted without further research:

### utoipa 4→5 Upgrade
**Completed (2026-04-26)**: The utoipa upgrade from 4 to 5 is now complete. Key changes:
- `utoipa = "5"` is now used in Cargo.toml
- Response/request types for complex config (MainConfig, MeshConfig, DnsConfig, etc.) now use `serde_json::Value`
- Types with fields like `DateTime<Utc>`, `PathBuf` use manual `ToSchema` impls in `src/admin/schema.rs`
- OpenAPI tests use `HttpMethod` enum instead of `PathItemType` (API change in utoipa 5)

### Org Key Trust Chain (7.11)
**Deferred**: Very large implementation requiring new modules. Trust chain: Genesis Key → Global Nodes (2/3 quorum) → Org Keys → Edge Nodes. The `organization.rs` module exists but full trust chain verification is not implemented.

### hickory-recursor 0.25 → 0.26
**Completed (2026-04-26)**: The hickory-dns migration is now complete. Key changes:
- `hickory-proto` and `hickory-resolver` updated to 0.26
- `Recursor` integration migrated to `hickory-resolver` recursor feature
- `Message` and `Record` APIs updated to use fields instead of methods
- `TokioRuntimeProvider` used as the connection handle
- DNSSEC validation status retrieved via `authentic_data` flag on `Message`

## Implementation Planning

The consolidated implementation plan is located at `plans/plan.md`. This plan contains only deferred/blocked items that require future attention.

### Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Check specific modules compile
cargo check --lib -p maluwaf --features <feature>

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```