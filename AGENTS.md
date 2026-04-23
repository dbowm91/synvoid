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

## Codebase Structure

### Key Modules

- `src/process/` - IPC communication, process management
- `src/overseer/` - Master process orchestration
- `src/master/` - Parent process implementation
- `src/worker/` - Worker process implementation
- `src/supervisor/` - Worker supervision
- `tests/` - Integration and benchmark tests

### Architecture Pattern

The overseer/master/worker architecture uses:
- Unix domain sockets for IPC
- `Message` enum in `src/process/ipc.rs` (re-exported via `src/process/mod.rs`) for communication
- `ProcessManager` for worker lifecycle
- Health checks via IPC heartbeat messages

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

**Note**: WireGuard transport has been removed from the codebase.

## Common Patterns

### Testing IPC Messages

```rust
use maluwaf::process::Message;

// Serialize/deserialize
let msg = Message::WorkerStarted { id: 1, pid: 12345, .. };
let json = serde_json::to_string(&msg).unwrap();
let decoded: Message = serde_json::from_str(&json).unwrap();
```

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

// Create manager with custom timeouts
let config = TrustAnchorConfig {
    pending_observation_days: 30,
    revocation_grace_days: 30,
    extended_removal_days: 60,
    trust_anchor_retention_days: 7,
    ..TrustAnchorConfig::default()
};
let manager = TrustAnchorManager::new(config);

// Observe a new key
let event = manager.observe_dnskey_at_root(key_tag, algorithm, &public_key, false);
assert!(matches!(event, Rfc5011Event::NewKeySeen { .. }));

// Check trust anchor with CDS digest
let event = manager.trust_anchor_check(key_tag, algorithm, digest_type, &digest);
assert!(matches!(event, Rfc5011Event::KeyPending { .. }));

// Process RFC 5011 updates
let events = manager.process_rfc5011_updates();
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

## File Naming Conventions

- Source files: `snake_case.rs`
- Test files: `snake_case_test.rs` or in `tests/` directory
- Modules: `mod.rs` for module aggregation

## DNSSEC and RFC 5011

### Trust Anchor Configuration

The `TrustAnchorConfig` struct supports separate timeout configuration for RFC 5011 state transitions:

| Field | Default | Purpose |
|-------|---------|---------|
| `pending_observation_days` | 30 | Time a new key spends in Pending state before becoming Valid (RFC 5011 Section 3.2) |
| `revocation_grace_days` | 30 | Time a revoked key spends before being Removed (RFC 5011 Section 4) |
| `extended_removal_days` | 60 | Time a removed key spends before being Purged from storage |
| `trust_anchor_retention_days` | 7 | Time a Valid key can be absent before being marked Missing |

### RFC 5011 State Machine

Keys transition through these states:
1. **Seen** - Key observed in DNSKEY RRset but not validated
2. **Pending** - Key validated via CDS/CDNSKEY digest, awaiting observation period
3. **Valid** - Key is trusted for DNSSEC validation
4. **Revoked** - Key has REVOKE bit set
5. **Removed** - Revoked key waiting for extended confirmation
6. **Missing** - Valid key not seen for retention period

**Missing→Pending restoration**: Only keys that were previously Valid (trust_point != 0) can auto-restore via `observe_dnskey_at_root()`. Keys that were never Valid must go through digest verification via `trust_anchor_check()` first.

## Planning and Implementation Patterns

The implementation plan was consolidated in `plans/plan.md`. This document contains all implementation items organized into waves for parallel sub-agent execution.

**Current Status** (as of 2026-04-23):
- ~60+ implementable items across 10 waves
- **97%+ COMPLETE** (57/60 items completed, 6 deferred)
- Deferred items: C.5 (JSON Serialization), G.5 (Edge Caching Image Poison), I.1 (ConnectionLimiter Sharding), I.4 (WebSocket WAF), J.6 (Static Worker IPC), J.7 (IPC TOCTOU)
- All security fixes implemented
- All performance hot-path optimizations implemented

When undertaking new features:
1. **Research First**: Read relevant `skills/` files and `AGENTS.md` sections.
2. **Avoid Complex Rewrites**: Maintain the existing architecture unless explicitly authorized to rewrite.
3. **Follow Existing Patterns**: The codebase has established patterns for common operations (see sections below).

### Wave Structure for Parallel Execution

Each wave can be approached with parallel sub-agents (except Wave A - compile blocker):

| Wave | Focus | Items |
|------|-------|-------|
| A | Critical Bug Fixes | 1 (compile blocker) |
| B | Security Critical | 7 |
| C | Performance Hot Paths | 8 |
| D | Mesh & DHT | 10 |
| E | Stub & Incomplete | 4 |
| F | OpenAPI & Admin | 6 |
| G | Documentation | 5 |
| H | Dependencies | 4 |
| I | WAF & Detection | 5 |
| J | Remaining | 7 |

## Subagent Execution Best Practices

When using subagents to make code changes:
1. **Always verify the actual code** — subagents may claim a fix was applied but the code still shows the old version. Always read the file directly to confirm.
2. **Run compilation checks** — `cargo clippy --lib -- -D warnings` to catch type errors
3. **Run tests** — `cargo test --test integration_test` to verify runtime behavior
4. **Run format check** — `cargo fmt` then `cargo fmt --check` to catch drift

**Critical verification step**: After any subagent reports completion:
```bash
# Check if file was actually modified
git diff HEAD -- <file>
# Or grep for the expected fix
rg "expected_pattern" <file>
```

Common failure mode: subagent reports success but code wasn't actually modified, or was modified incorrectly. This is especially common with:
- Complex refactoring requiring multi-file changes
- Architectural changes requiring wiring new components
- Proto file changes requiring code generation
- Cases where fix requires understanding existing code patterns
- Documentation changes (harder to verify than code)

For complex changes, prefer direct implementation or verify each step incrementally.

**Verification for documentation tasks**: When verifying docs changes, use `grep` to search for expected content patterns rather than just reading the file. Subagents may claim docs were updated but the content may be incomplete or incorrect.

### Module Splitting Decisions

- **Do NOT split cohesive request pipelines** like `http/server.rs` and `tls/server.rs` - these handle a single logical flow
- **Do NOT rewrite files from scratch** - incremental changes are safer
- **Prefer section comments** over refactoring for readability
- **Verify each subagent change compiles** before moving to the next

### Tonic Upgrade Gotchas

When upgrading tonic from 0.12 to 0.14:
- `tonic_build::configure()` API removed - use `tonic-prost-build` crate instead
- Add `tonic-prost` dependency for generated code codec
- Update `build.rs` to use `tonic_prost_build::configure()`

## Known Code Quality Context

### Compile Blocker

**⚠️ CRITICAL**: The codebase currently fails to compile due to a syntax error in `src/fastcgi/mod.rs:333`. This MUST be fixed before any other work can proceed.

```
error: unexpected closing delimiter: `}`
   --> src/fastcgi/mod.rs:333:5
```

### Clippy and Dead Code Suppressions

`cargo clippy -- -D warnings` passes clean when the codebase compiles.

### Build Configuration

`Cargo.toml` uses relaxed version pins (e.g., `"0.11"`).

### Dependency Cleanup

The following dead dependencies were removed:
- `bincode` — never imported; `serialize_bincode`/`deserialize_bincode` shims use `postcard` internally
- `wasmtime-wasi` — unused (only `wasmtime` core needed)
- `ab_glyph`, `flare`, `memmap2` — zero imports anywhere
- `url` — transitive via axum; no direct imports
- `futures-util` — re-exported by `futures` crate
- `once_cell` — replaced with `std::sync::LazyLock` across 13 files
- `rustls-pemfile` — replaced with `rustls_pki_types::pem::PemObject`

Feature flags trimmed: `tower` removed `"timeout"`, `tower-http` removed `"trace"`.

**DNS dependencies are now optional** behind the `dns` feature: `hickory-proto`, `hickory-resolver`, `hickory-recursor`, `dns-parser`, `tokio-dstip`, `cryptoki`, `getrandom`.

**Note**: `nix` features `"net"` and `"uio"` are REQUIRED despite initial assessment they were unused. `platform/unix.rs` needs `"net"` for `SockaddrIn`/`SockaddrIn6` and `"uio"` for `ControlMessage`/`sendmsg`/`recvmsg`.

**Note**: `once_cell` and `bincode` still appear in `Cargo.lock` as transitive dependencies (via tracing-core, gloo-worker, etc.). This is expected.

### Error Handling Status

`src/error.rs` has been deleted. `WafError`, `WafResult`, and `WafErrorExt` no longer exist. Every module uses `anyhow`, `Box<dyn Error>`, or custom types.

### Duplicate Timestamp Utility

All duplicate `current_timestamp()` definitions have been consolidated into `src/utils.rs`. Use `crate::utils::current_timestamp()` as the canonical version.


## Performance Hot Paths

**Architecture Note - Worker Process Scaling:**

The unified worker uses a single `tokio` async event loop which is far more efficient than spawning multiple worker processes:
- **Single async process**: A single `UnifiedServer` with one tokio runtime handles thousands of sites concurrently via cooperative scheduling
- **Internal parallelism**: Use `tokio::spawn()` and async concurrency primitives (semaphores, channels) within the worker, NOT process-level parallelism
- **Why NOT multi-process scaling**: Multiple worker processes compete for CPU cores, increase context switching, and add IPC overhead
- **TcpListenerPool**: The worker uses an internal thread pool for accepting connections, auto-tuned via `std::thread::available_parallelism()` (default: CPU cores, fallback: 4)

**Do NOT increase `unified_server_workers` for scaling purposes.** Instead, tune `tcp.worker_pool_size` or use async primitives within the existing event loop.

**Architecture Note - WAF Sequential Checks:**

WAF checks run sequentially, not in parallel. This is intentional:
- **Attack blocking**: Some checks should block subsequent checks when an attack is detected (e.g., SQL injection found → don't waste time on XSS checks)
- **Fast checks**: WAF checks are fast hash lookups and string comparisons, not I/O-bound
- **No lifetime issues**: Parallelizing with `tokio::spawn` would require `'static` lifetimes for closures, complicating the architecture

Agents modifying these areas should be aware of performance characteristics:

| Area | Concern | Location |
|------|---------|----------|
| WAF detection | Runs ~20+ checks per request, lock acquisition per request | `src/waf/mod.rs:660-700` |
| Cache lookups | O(1) via `moka::Cache`; eviction-based cleanup | `src/proxy_cache/store.rs` |
| Input normalization | Pre-computed lowercased words at init | `src/waf/probe_tracker.rs:475` |
| Rate limiting | Lock-free atomic bitset for slot tracking | `src/waf/ratelimit/core.rs` |
| HTTP path sanitization | Not called in request path | `src/proxy.rs:139` |
| Response header filtering | Pre-allocated buffer via `filter_response_headers_buf` | `src/tls/server.rs:1405-1406,1551-1552` |
| SSRF detection | `Cow<str>` optimization to avoid repeated lowercasing | `src/waf/attack_detection/ssrf.rs` |
| DNS zone store | 64-sharded `RwLock`; suffix index for O(k) lookups | `src/dns/server/sharded_store.rs` |
| Body buffering | Uses `BytesMut` to avoid reallocations | `src/http/shared_handler.rs` |
| Retry logic | Uses `<` not `<=` to prevent off-by-one | `src/proxy/mod.rs:860,886,906` |

## Module Size Guide

| Module | Lines | Status |
|--------|-------|--------|
| `src/mesh/transport.rs` | ~2,609 | Already split into 9 submodules |
| `src/mesh/protocol_proto_encode.rs` | ~2,024 | Generated protobuf pattern — acceptable |
| `src/http/server.rs` | ~3,238 | **Exception**: Cohesive request pipeline with section comments |
| `src/tls/server.rs` | ~1,747 | **Exception**: Mirrors http/server.rs, same reasoning |
| `src/mesh/config.rs` | ~1,545 | Already fragmented with sibling files |
| `src/mesh/topology.rs` | ~1,516 | Already split with types.rs |
| `src/mesh/protocol.rs` | ~1,196 | Split into submodules |
| `src/dns/server/mod.rs` | ~763 | Split into submodules |
| `src/worker/mod.rs` | ~786 | Split into submodules |
| `src/admin/state.rs` | ~561 | Split into submodules |

**Note on large files**: `http/server.rs` and `tls/server.rs` are exceptions to the size guidelines. They contain cohesive request handling pipelines where splitting would introduce risk without meaningful benefit. Section comments delineate the 15 distinct phases within `handle_request()`.

## Key Implementation Details

### Atomic Counter Safety

When decrementing atomic counters, use `fetch_update` with `checked_sub` to prevent underflow:

```rust
// BEFORE (wraps on underflow)
self.current_connections.fetch_sub(1, Ordering::Relaxed);

// AFTER (no-op at zero)
let _ = self.current_connections
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
```

### TLS Client Architecture

Three-tier HTTP client hierarchy:

| Function | TLS | Use Case |
|----------|-----|----------|
| `create_http_client()` | `https_or_http()`, native roots + webpki fallback | Internal: honeypot, alerting |
| `create_http_client_with_config()` | `https_only()`, native roots + webpki fallback | Default: proxy, TLS server |
| `create_upstream_client()` | Configurable via `UpstreamTlsConfig` | Per-site upstream with `skip_verify`/`allow_plaintext` |

Upstream TLS clients are cached by config hash in a `DashMap` for reuse across requests.

**NoVerifier replacement**: `HostnameSkippingVerifier` wraps `WebPkiServerVerifier` — validates certificate chain and signatures, only skips hostname verification. Logs WARN on every use.

### ACME HTTP-01 Challenge Serving

ACME HTTP-01 challenges work across edge/origin mesh topologies. When an origin needs a certificate, the edge node must be able to serve the challenge response.

**Two serving paths:**

1. **Direct HTTP** (`src/http/server.rs:551-579`): The edge's HTTP server handles incoming ACME requests directly from the ACME server (port 80/TCP). The global node has already pushed `UpstreamOwnershipChallenge{Http01{token, key_authorization}}` to all registered edges via mesh QUIC. The edge stores this in its `ownership_challenge_store` and serves it when the ACME server probes.

2. **Mesh QUIC stream** (`src/mesh/transport_peer.rs:2345-2366`): When the global node proxies ACME requests through mesh QUIC (with `Host: origin-host`), `handle_http_proxy_stream()` checks for `GET /.well-known/acme-challenge/{token}` and serves directly from the challenge store — without proxying to a backend.

**Flow:**
```
Origin initiates ACME order
    → Global Node sends UpstreamOwnershipChallenge to all edges (mesh QUIC)
    → Edges store token → key_authorization in LRU cache (5 min TTL)
    → ACME server probes edge IP: GET /.well-known/acme-challenge/{token}
    → Edge serves key_authorization from store
```

**Threat model:** Only serves challenges the edge received via HMAC-signed mesh messages. Cannot forge challenges since it only has the public `key_authorization` string (the ACME server verifies using the origin's private key). Race condition risk if edge is offline when global node pushes the challenge.

### ACME Client

`src/tls/acme.rs` implements a full ACME client using the `instant-acme` crate. Supports HTTP-01 and DNS-01 (feature-gated `dns`) challenges. Certificate renewal runs every 24h via `spawn_renewal_task()`. Config under `[tls.acme]` in TOML.

### TLS Passthrough

Site-level config to forward raw TLS bytes from client to origin without decryption. WAF applies layer 3/4 only (IP rate limiting, connection limits). SNI is extracted via `src/tls/sni_peek.rs` before TLS handshake. Enabled via `tls_passthrough = true` in site proxy config.

### Cert Distribution (Origin → Edge)

`src/mesh/cert_dist.rs` handles origin→edge TLS certificate distribution via 3 mesh messages (`SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse`). Private keys encrypted with AES-256-GCM using per-site keys derived via HKDF from the mesh session key.

### IPC Session Key

The IPC session key is passed via a temp file (`MALUWAF_IPC_KEY_FILE`) instead of an env var. The temp file uses `0600` permissions (Unix only) and is deleted by the worker after reading. Falls back to `MALUWAF_IPC_KEY` env var only if `allow_insecure_ipc_key = true` (default: fail-hard).

### Peer Role Validation

Use `crate::mesh::peer_auth::validate_peer_role()` for centralized global node authentication. This function validates that peers claiming a global role provide the correct `global_node_key`. Used by both Discovery and WireGuard transports.

### TOFU Certificate Pinning

Seed node certificate fingerprints are managed by `MeshCertManager` in `src/mesh/cert.rs`. On first connection, fingerprints are pinned automatically (Trust On First Use) unless `require_explicit_fingerprint = true` in `[mesh.seed_tofu]` config. On subsequent connections, fingerprints are verified in `connect_to_peer()` via `verify_seed_fingerprint()`. Pre-configured fingerprints can be set in TOML config via `pinned_cert_fingerprint` on seed nodes.

**Config options:**
```toml
[mesh.seed_tofu]
enabled = true  # Enable TOFU (default: true)
require_explicit_fingerprint = false  # Reject first connection without explicit fingerprint (default: false)
```

### Auth Store Merge Pattern

When multiple pending stores need persisting, merge them rather than saving only the last one:

```rust
fn merge_stores(stores: &[AuthStore]) -> AuthStore {
    let mut merged = stores.last().unwrap().clone();
    for store in stores.iter().take(stores.len() - 1) {
        merged.login_logs.extend(store.login_logs.iter().cloned());
    }
    merged
}
```

### Global Nodes as Trust Anchors

Global nodes are the single source of truth and Certificate Authority (CA) for the entire network. This is a fundamental security design decision:

- **Global nodes are NOT elected** — they are explicitly configured and bootstrapped
- Global nodes function analogously to Tor's directory authorities (but with opposite purpose: exposing services rather than providing anonymity)
- All node certificates are signed by global nodes — they serve as the root CA
- Global nodes maintain complete network topology and act as directory servers

Any system that claims to "elect" or "vote" for global nodes violates this security model.

### Module Split Pattern

When splitting large modules:
1. Struct definitions stay in parent file; submodules add `impl StructName { ... }` blocks
2. Each submodule is a sibling file (`foo_bar.rs`), NOT a subdirectory
3. Submodules use `use super::*` or `use crate::module::*` for imports
4. Fields accessed from submodules must be `pub(crate)`, not private
5. Module declarations go in parent module file, not in the struct's file

### ShardedZoneStore

The DNS zone store (`src/dns/server/sharded_store.rs`) uses 64 shards to reduce lock contention. Each shard is an independent `parking_lot::RwLock<HashMap<String, Zone>>`. Zones are distributed by hashing the origin string (djb2 variant).

Key API:
- `get(&str) -> Option<Zone>` — single-shard read, clones zone
- `insert(String, Zone)` — single-shard write
- `for_each(FnMut(&String, &Zone))` — iterates all shards (read locks)
- `for_each_mut(FnMut(&mut Zone))` — iterates all shards (write locks)
- `find_by_suffix(&str) -> Option<Zone>` — O(k) suffix match via index
- `find_by_suffix_with_filter(&str, Fn(&Zone) -> bool) -> Option<Zone>` — O(k) suffix + filter
- `find(Fn(&str, &Zone) -> bool) -> Option<Zone>` — search all shards (avoid in hot path)
- `get_or_create_and_update(&str, FnOnce(&mut Zone))` — entry-or-insert on one shard
- `keys() -> Vec<String>` — collect all zone names (all shards)

When modifying zone access code, prefer single-shard operations (`get`, `insert`, `update_zone`) over full-shard iteration (`for_each`, `keys`). The `Arc<ShardedZoneStore>` replaces the former `Arc<RwLock<HashMap<String, Zone>>>` pattern.

**Performance note**: For DNSSEC validation, use `find_by_suffix_with_filter()` instead of `find()` to get O(k) suffix lookup followed by filter, instead of O(n) iteration over all zones.

### DHT Capability-Based Write Authorization

The DHT implements capability-based authorization via `CapabilityAccessVerifier` (`src/mesh/dht/capability_access.rs`). This ensures nodes can only store records for capabilities they possess.

**Key types:**
- `CapabilityAttestation` - Attests that a node has a specific capability (e.g., "waf", "threat_intel"), signed by a global node
- `CapabilityAccessVerifier` - Verifies attestations for DHT write operations

**Verification flow:**
1. `RecordStoreManager` has a `capability_verifier: Option<Arc<CapabilityAccessVerifier>>` field
2. Before storing a record, `store_record()` in `record_store_crud.rs` calls `verify_capability_for_key()`
3. `verify_capability_for_key()` checks if the key requires a capability (via `key_requires_capability()`)
4. If required, the node must have a valid `CapabilityAttestation` from a global node

**Keys that require capability:**
- `yara_rules_manifest:{node_id}` — requires "waf" capability
- `yara_rule:{content_hash}` — requires "waf" capability
- `threat_indicator:{ip}:{threat_type}` — requires "threat_intel" capability

**Configuration:** Use `record_store.set_capability_verifier(Some(verifier))` to enable capability verification.

## Moka Cache Migration

When migrating from `LruCache` to `moka::sync::Cache`:
1. `moka::Cache` is already thread-safe — do NOT wrap in `Mutex` or `RwLock`
2. Remove all `.lock()` calls on the cache
3. Use `.get()`, `.insert()` directly (these methods are thread-safe)
4. For TTL: use `.time_to_live()` not `.expire_after()` (latter requires custom `Expiry` trait implementation)
5. For byte-size eviction: use `.max_capacity()` + `.weigher()` where the weigher returns `u32`
6. `max_capacity` expects `u64`, not `usize`

## Role Comparison Best Practices

Always use `role.is_global()` instead of `role == MeshNodeRole::Global` because:
- `MeshNodeRole` is a bitmask (Global=0b010, Edge=0b001, Origin=0b100)
- Composite roles like `GLOBAL_EDGE` (0b011) have the Global bit set
- Direct equality only matches pure roles, missing composite role cases

## RRSIG Timestamp Encoding

RFC 4034 requires 32-bit (u32) timestamps in RRSIG records. When writing:
```rust
// CORRECT:
rrsig.extend_from_slice(&(timestamp as u32).to_be_bytes());

// WRONG (writes 64-bit):
rrsig.extend_from_slice(&timestamp.to_be_bytes());
```

## Mesh Upstream Routing Architecture

**Nginx-like Domain Routing Model**:

| Component | Format | Example |
|-----------|--------|---------|
| Upstream ID | `http://host:port` | `http://example.com:80` |
| mesh.local_upstreams key | Domain-based | `"http://example.com:80"` |
| Local backend | Private URL | `http://127.0.0.1:5001` |

**Key files**:
- `src/mesh/proxy.rs:extract_upstream_id()` — produces `http://host:port`
- `src/mesh/topology.rs` — stores local_upstreams with domain-based keys
- `src/mesh/transport.rs:announce_upstream()` — announces using domain-based ID
- `src/mesh/dht/keys.rs` — DHT key types including `VerifiedUpstream`

**Routing flow**:
1. Edge receives request → `extract_upstream_id()` → `http://example.com:80`
2. Query DHT for `verified_upstream:http://example.com:80`
3. Get origins that registered this domain+port
4. Weighted random selection → route to selected origin

**Config format**:
```toml
[mesh.local_upstreams]
"http://example.com:80" = {
    upstream_url = "http://127.0.0.1:5001",
    supported_ports = [80, 443],
}
```

**Fixed**: Origin local backend selection is now implemented. Origin nodes accept incoming QUIC streams and route HTTP requests to local backends based on Host header. See `src/mesh/transport.rs:mesh_accept_loop` and `src/mesh/transport_peer.rs:handle_http_proxy_stream`.

## DNS & DNSSEC Architecture

**DNSSEC validation is by design limited to the `Recursive` provider.**

The following providers do NOT perform DNSSEC validation (they are stub/forwarding resolvers):
- `Google` - forwards to Google's DNS, we don't re-validate
- `Cloudflare` - forwards to Cloudflare's DNS, we don't re-validate
- `System` - uses system resolver, no validation
- `Custom` - uses custom upstream IPs, no validation

**To enable DNSSEC validation**, use the `Recursive` provider:

```toml
[dns.recursive]
upstream_provider = "Recursive"
dnssec_validation = true
trust_anchors.enabled = true
trust_anchor_path = "trusted-key.key"
```

## YARA & ThreatIntel Rule Distribution

**Architecture**: Both YARA rules and ThreatIntel use DHT as the primary propagation mechanism. Mesh broadcast is retained as fallback only (to be removed in future).

### Propagation Flow

```
GLOBAL NODE updates rules
         │
         ├──▶ publish_rules_to_dht() ──▶ store rule content + manifest
         │
         └──▶ broadcast_pending_records() ──▶ DhtRecordAnnounce to k closest peers
                           │
                           ▼
              PEERS receive and store in local DHT cache
                           │
                           ▼
    NON-GLOBAL: sync_from_dht() iterates local cache, applies newest version
```

### Key Characteristics

| Aspect | Finding |
|--------|---------|
| DHT announce | One-hop broadcast to k closest peers (NOT recursive Kademlia) |
| Who announces | Global nodes only |
| Who receives | All node types (global, edge, origin) |
| Re-announce | YARA uses `re_announce_interval_secs`; ThreatIntel uses `re_announce_interval_secs` |

### YARA DHT Keys

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `yara_rule:{content_hash}` | Actual rule content (content-addressed) | 24 hours |
| `yara_rules_manifest:{node_id}` | Global node's current ruleset metadata | 24 hours |

### YARA Signature Verification

YARA rules published to DHT are signed using Ed25519:
- **Manifest signature**: `version:content_hash:node_id:timestamp`
- **Rule content signature**: `version:rules:content_hash:node_id:timestamp`

During DHT sync (`sync_from_dht()`), both manifest and rule content signatures are verified before accepting rules. The manifest's `content_hash` is verified against the actual rule content hash. Records without signatures are accepted for backward compatibility with legacy data.

### ThreatIntel DHT Keys

| Key Pattern | Purpose |
|-------------|---------|
| `threat_indicator:{ip}:{threat_type}` | Per-type indicator (composite key, e.g., `threat_indicator:1.2.3.4:IpBlock`) |

**Important**: ThreatIntel uses composite keys with threat_type suffix to prevent collision between different threat types for the same IP. A key without threat_type (e.g., `threat_indicator:1.2.3.4`) will NOT match.

### ThreatIntel Signature Verification

ThreatIntel indicators published to DHT are signed using Ed25519:
- **Indicator signature**: `indicator_value:threat_type:severity:timestamp:source_node_id`

During DHT sync (`sync_from_dht()`), signatures are verified before accepting indicators. The `signer_public_key` is extracted from the DHT record and used to verify the signature. Records without valid signatures are skipped but allow backward compatibility with unsigned legacy records.

### ThreatIntel Re-announcement

Global nodes periodically re-announce ThreatIntel indicators via `re_announce_local_indicators()`. The interval is controlled by `re_announce_interval_secs` (default: 300s). ALL non-expired indicators are re-announced regardless of `local_origin` flag. Respects `hub_only_mode` (non-global nodes do not re-announce).

## Honeypot Architecture Summary

| Subsystem | Location | Publishing |
|-----------|----------|------------|
| HTTP Honeypot | `src/challenge/honeypot.rs` | Via `block_ip_with_threat_intel()` |
| Port Honeypot | `src/honeypot_port/` | Via `start_mesh_threat_publishing()` |

## Web App Stack Backend Types

| Backend | Config | Implementation |
|---------|--------|----------------|
| Static Files | `[site.static]` | `src/static_files/mod.rs` |
| PHP-FPM | `[site.php]` | `src/php/mod.rs` |
| FastCGI | `[site.fastcgi]` | `src/fastcgi/mod.rs` |
| WASM/Serverless | `[site.serverless]` | `src/serverless/manager.rs` |
| Python (Granian) | `[site.app_server]` | `src/app_server/granian.rs` |
| HTTP Upstream | `[site.upstream]` | `src/proxy.rs` |
| Mesh Origin | DHT + `[site.upstream]` | `src/mesh/topology.rs` |

### FileManager YARA Integration

The `FileManager` (`src/static_files/file_manager.rs`) uses mesh YARA rules for malware scanning on upload. It implements `reload_yara_rules_if_needed()` which syncs with the global `YaraRulesManager` from `src/waf/mod.rs`. When `scan_on_upload` is enabled, the FileManager:

1. Initializes with bundled YARA rules as fallback
2. Periodically checks for newer versions from mesh YARA rules
3. Reloads rules via `yara_scanner.reload_with_rules()` when version changes

This allows FileManager to leverage YARA rules distributed via the mesh network.

## FastCGI Pool Management

The FastCGI module (`src/fastcgi/`) provides connection pooling via `FastCgiPoolManager`:

```rust
// Get a pool for a given host:port
let pool = fastcgi::get_pool(host, port);

// Remove a pool (e.g., on config change)
fastcgi::remove_pool(host, port);

// Close all pools (e.g., on shutdown)
fastcgi::close_all_pools();
```

Pools are stored as module-level statics via `LazyLock`, keyed by `host:port`. Each pool manages reusable FastCGI connections.

## PHP Security Settings

`PhpConfig` security fields are enforced via PHP-FPM:

```toml
[site.php]
disable_functions = "exec,passthru,shell_exec,system"
open_basedir = "/var/www/html"
allow_url_fopen = false
max_execution_time = 30
memory_limit = "128M"
upload_max_filesize = "10M"
post_max_size = "50M"
```

These are passed to PHP-FPM as:
- `PHP_ADMIN_VALUE:disable_functions` (admin-only, cannot be overridden)
- `PHP_ADMIN_VALUE:open_basedir` (admin-only, cannot be overridden)
- `PHP_VALUE` for other settings

## PHP Per-Location Security

Security settings can be configured per-location via `PhpLocationConfig`:

```toml
[site.proxy.php.locations]
path = "/api"
disable_functions = "exec,passthru,shell_exec"
open_basedir = "/var/www/api"
max_execution_time = 60
```

Location-level settings override site-level settings for that specific path prefix.

## Static File Directory Templates

Custom templates for directory listing are supported via `SiteStaticThemeConfig`:

```toml
[site.static.theme]
directory_template_path = "/etc/maluwaf/templates/directory.html"
preset = "dark"
```

Supported placeholders:
- `{{url_path}}` - current URL path
- `{{parent_link}}` - parent directory link
- `{{rows}}` - file/folder entries
- `{{site_name}}` - site name (RustWAF)
- `{{title}}` - page title ("Index of {url_path}")

## Skills and Knowledge Base

For complex subsystems, specialized skill files provide detailed architecture guidance:

### Mesh & DHT Architecture

**Location**: `skills/malu_mesh.md` (in-repository copy)

This skill file documents the mesh networking and DHT system, which is complex and has many interdependent components. The skill file contains:
1. **Architecture diagrams** (via text descriptions)
2. **Key derivation chains** (genesis → signing_key → tier_key_master)
3. **Phase status tracking** - what's completed vs deferred
4. **Common issues** - known gaps and debug patterns
5. **File reference table** - purpose of each mesh-related file

The skill file was originally maintained at `~/.config/opencode/skills/malu_mesh/SKILL.md` but a copy is kept in-repository for reliability.

### DNS & DNSSEC

**Location**: `skills/dns_dnssec.md` (for AI agents)

Detailed architecture documentation for the DNS and DNSSEC subsystems.

**User-facing documentation**: `docs/RFC5011_TRUST_ANCHOR.md` and `docs/DNS_DNSSEC.md`

### Threat Intelligence

**User-facing documentation**: `docs/THREAT_INTEL.md`

Covers ThreatIntel indicators, YARA rules, DHT-based distribution, and signature verification.

### Other Skills

- `skills/admin_ui.md` - Admin UI architecture and patterns
- `skills/httpserver.md` - HTTP server implementation details
- `skills/performance_patterns.md` - Performance optimization patterns
- `skills/security_patterns.md` - Security implementation patterns
- `skills/static_files.md` - Static files and directory listing
- `skills/waf_bot_detection.md` - WAF and bot detection architecture

## Important Notes

1. **Never commit secrets** - Use `.gitignore` for credentials
2. **Test isolation** - Use temp dirs for socket tests
3. **Async tests** - Use `#[tokio::test]` for async code
4. **Platform-specific tests** - Use `#[cfg(unix)]` or `#[cfg(windows)]`
5. **Key tag calculation** - Use `crate::dns::dnssec::calculate_key_tag` for RFC 4034 compliant key tags

### Startup Validation Patterns

The codebase uses placeholder values that should trigger warnings at startup:

| Placeholder | Location | Status |
|-----------|----------|--------|
| `DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER` | `src/waf/rule_feed.rs:321` | ✅ Fixed - logs warning |
| `TOKEN_PLACEHOLDER` | `src/config/admin.rs` | ✅ Fixed - added to WEAK_TOKEN_PATTERNS |

These placeholders indicate the value was not configured and may indicate a security issue.

### Implemented Stub Functions

The following functions were stubbed but have been implemented:

| Function | Location | Implementation |
|----------|----------|----------------|
| `resolve_txt_record()` | `src/mesh/transport_dns.rs:1183` | ✅ Uses dns_resolver.lookup_txt() |
| `is_global_node_ip_string()` | `src/mesh/threat_intel.rs:358` | ✅ Delegates to is_global_node_ip() |
