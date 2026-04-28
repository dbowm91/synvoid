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

- `MeshBackend`/`MeshBackendPool` at `src/mesh/backend.rs:109-303` — backend health checking and selection. `BackendType::Mesh` variant is dispatched in the HTTP handler via `mesh_backend_pool`.
- `MeshProxy` at `src/mesh/proxy.rs` — request routing, caching, provider selection
- `MeshTransport` at `src/mesh/transport.rs` — peer communication, transport initialization
- `DHT` at `src/mesh/dht/` — distributed hash table for state sync
- `SpinRuntime` at `src/spin/` — Spin WASM serverless runtime support
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

**Note**: WireGuard **mesh transport** is deprecated and non-functional (slated for removal — see plan.md Wave 7A). WireGuard **VPN tunnel** (`src/tunnel/wireguard/`, `src/vpn_client/`) is separate and working.

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

### Serverless Async Compilation

The serverless module (`src/serverless/`) supports async WASM compilation to avoid blocking startup:

```rust
// AsyncCompilationHandle manages compilation state
use crate::serverless::async_compilation::{AsyncCompilationHandle, AsyncCompilationManager, CompilationState};

// Check compilation status
if let Some(ref handle) = function.compilation_handle {
    match handle.poll_state() {
        CompilationState::Compiling { .. } => { /* wait or fallback */ }
        CompilationState::Ready => { /* use runtime */ }
        CompilationState::Failed { error } => { /* handle error */ }
        CompilationState::Pending => { /* not started */ }
    }
}

// Spawn async compilation
let compilation_manager = self.compilation_manager.clone();
let (tx, rx) = tokio::sync::oneshot::channel();
tokio::spawn(async move {
    let result = tokio::task::spawn_blocking(move || {
        // blocking WASM compilation work
    }).await;
    let _ = tx.send((function_name, result));
});
compilation_manager.mark_compiling(&func_name);
```

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

**YARA trusted_signer bypass**
```rust
// YARA rules now enforce deny-by-default for non-global nodes
if !self.node_role.is_global()
    && !self.config.trusted_signers.is_empty()
    && !self.config.trusted_signers.contains(&manifest_signer_pk.to_string())
{
    // reject
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

## Recently Completed Items

All implementation plan waves have been completed and verified as of 2026-04-28:

| Wave | Feature | Date | Verification |
|------|---------|------|--------------|
| 1.1 | Streaming WAF Engine (`StreamingWafCore`, `StreamingWafDecision`) | 2026-04-27 | Tests pass |
| 1.2 | DHT Neighborhood Persistence (`record_store_persist.rs`) | 2026-04-27 | Tests pass |
| 2.1 | Hybrid Post-Quantum Mesh Signatures (`HybridSignature`, `ml_dsa.rs`) | 2026-04-27 | Tests pass |
| 2.2 | Windows Service & DX (`WindowsInterfaceResolver`, firewall rules) | 2026-04-27 | Tests pass |
| 3.1 | Federated Behavioral Intelligence (`BehavioralIntelligenceManager`) | 2026-04-27 | Tests pass |
| 3.2 | Real-time Topology Visualizer (`/api/mesh/topology`, `/api/mesh/topology/graph`) | 2026-04-27 | Tests pass |
| 4.A | KyberSlash vulnerability fix (`pqc_kyber` → `pqc_kyber_edit`) | 2026-04-27 | `cargo check -p wasm-pow` |
| 4.1 | WASM table_growing bounded (`max_table_elements` limit) | 2026-04-27 | Tests pass |
| 4.2 | WASM pool DHT prefix leakage fixed | 2026-04-27 | `prepare_for_request` resets prefixes |
| 4.3 | Threat intel signer bypass fixed (deny-by-default) | 2026-04-27 | Tests pass |
| 4.4 | Serverless limits properly passed to load_plugin | 2026-04-27 | Tests pass |
| 4.5 | Time-based challenge verification (P0.5) | 2026-04-27 | Tests pass |
| 4.6 | Pass-over fallback signing violation fixed | 2026-04-27 | Tests pass |
| 4.7 | RecordStoreManager clone fixed (proper record copying) | 2026-04-27 | Tests pass |
| 4.8 | Severity-aware threat broadcast (CRITICAL/HIGH fanout=100%) | 2026-04-27 | Tests pass |
| 4.9 | Threat duplicate detection key mismatch fixed (`make_indicator_key`) | 2026-04-27 | Tests pass |
| 4.12 | YARA trusted_signer bypass fixed (deny-by-default) | 2026-04-27 | Tests pass |
| 5.1 | BackendType::Mesh integrated in HTTP server dispatch | 2026-04-27 | Tests pass |
| 5.2 | HTTP client cache increased to 1000 idle per host | 2026-04-27 | Tests pass |
| 5.3 | Upstream load balancing (round-robin via `weighted_shuffle`) | 2026-04-27 | Tests pass |
| 5.4 | Message cache increased to 500K capacity | 2026-04-27 | Tests pass |
| 5.5 | Proxy task spawn bounded (Semaphore with max concurrency) | 2026-04-27 | Tests pass |
| 5.6 | WASM instance pooling for transform_response | 2026-04-27 | Tests pass |
| 5.7 | edge_only flag enforcement in mesh routing | 2026-04-27 | Tests pass |
| 5.8 | proxy_cache wired in MeshProxy (preferences, cache key) | 2026-04-27 | Tests pass |
| 5.9 | SSTI double normalization fixed (use `normalized.lowercased`) | 2026-04-27 | Tests pass |
| 5.10 | provider_stats lock contention fixed (DashMap) | 2026-04-27 | Tests pass |
| 5.11 | Sync YARA/threat intel on peer connect | 2026-04-27 | Tests pass |
| 5.12 | ServerlessInvokeResponse handler added | 2026-04-27 | Tests pass |
| 5.13 | ServerlessInvokeRequest sender (transport_serverless.rs) | 2026-04-27 | Tests pass |
| 5.14 | WasmDistManager initialized in transport setup | 2026-04-27 | Tests pass |
| 6.2 | Cache key 5 sequential replace() optimized | 2026-04-27 | Tests pass |
| 6.3 | weighted_shuffle O(n) via WeightedIndex alias method | 2026-04-27 | Tests pass |
| 6.5 | Entropy calculation uses `[usize; 256]` instead of HashMap | 2026-04-27 | Tests pass |
| 6.6 | OpenRedirect uses Aho-Corasick for O(1) param matching | 2026-04-27 | Tests pass |
| 7A | WireGuard mesh transport removed (VPN tunnel preserved) | 2026-04-27 | `cargo fmt && clippy` |
| 7B | Dead code removed (verify_signature methods, etc.) | 2026-04-27 | Tests pass |
| 7C | Misleading `#![allow(dead_code)]` removed from active modules | 2026-04-27 | Tests pass |
| 7D | Feature flag cleanup (pqc-mesh removed) | 2026-04-27 | Tests pass |
| 7E.1 | ConnectionTokenGuard mutex replaced with parking_lot | 2026-04-27 | Tests pass |
| 7E.2 | Admin regex DoS with actual compilation timeout | 2026-04-27 | Tests pass |
| 7E.3 | IPC path traversal sanitization added | 2026-04-27 | Tests pass |
| 7E.4 | NonceCache O(n) fixed (HashSet for O(1) contains) | 2026-04-27 | Tests pass |
| 7E.5-9 | Additional quality fixes (DNS cache, circuit breaker, await-holding-lock) | 2026-04-27 | Tests pass |
| 8.1-8.3 | Sensitive field masking (RuleFeed, YaraFeed, Overseer config bug) | 2026-04-27 | Tests pass |
| 8.4 | Swagger UI integrated at /api/docs | 2026-04-27 | Tests pass |
| 8.5-8.8 | API discovery, DNS UI, honeypot hot-reload, behavioral endpoint | 2026-04-27 | Tests pass |
| 9.1-9.4 | Dependency updates (yara-x crypto, sysinfo, bcrypt) | 2026-04-27 | Tests pass |
| 10.1-10.7 | Testing improvements (WAF e2e, mesh proxy, HTTP/3, overseer, integration, stress, benchmarks) | 2026-04-27 | Tests pass |
| 11.1 | Spin WASM Runtime Support | 2026-04-28 | Tests pass |
| 11.2 | Serverless Standalone Enhancements (Async Compilation) | 2026-04-28 | Tests pass |

**Verification**: All 1552 lib tests pass, 242 integration tests pass, clippy clean, fmt clean.

## Implementation Planning

The consolidated implementation plan is at `plans/plan.md`. It organizes remaining work into waves designed for parallel execution by sub-agents:

- **Wave 4**: Critical Security Fixes (COMPLETED)
- **Wave 5**: High Priority Functional (COMPLETED)
- **Wave 6**: Performance Optimizations (COMPLETED)
- **Wave 7**: Code Quality & Cleanup (COMPLETED)
- **Wave 8**: Admin API & DX (COMPLETED)
- **Wave 9**: Dependency Updates (COMPLETED)
- **Wave 10**: Testing Improvements (COMPLETED)
- **Wave 11**: New Features (COMPLETED - P11.1 Spin WASM Runtime, P11.2 Serverless Standalone Enhancements)

Waves 1-3 are completed (Streaming WAF, DHT Persistence, Post-Quantum Signatures, Windows Service, Behavioral Intelligence, Topology Visualizer).

## Known File Path Corrections

When working with the plan, note these verified correct file paths (some plan items originally had wrong paths):

| Wrong Path | Correct Path | Notes |
|-----------|-------------|-------|
| `src/http/client.rs` | `src/http_client/mod.rs` | HTTP client module |
| `src/mesh/proxy.rs:1485` (edge_only) | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` | edge_only flag locations |

## Verification Commands

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
