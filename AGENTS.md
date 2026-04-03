# AGENTS.md - Developer Guide for AI Agents

This document provides guidance for AI agents working on the MaluWAF codebase.

## Project Overview

MaluWAF is a WAF (Web Application Firewall) with a multi-process architecture:
- **Overseer** (`src/overseer/`): Manages master process lifecycle, upgrades, health monitoring
- **Master** (`src/master/`): Parent process that spawns/manages workers, handles IPC
- **Worker** (`src/worker/`): Handles HTTP requests and communicates via IPC

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
- `wireguard` - WireGuard VPN support
- Serverless functions use WASM (wasmtime), not Deno

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

## Important Notes

1. **Never commit secrets** - Use `.gitignore` for credentials
2. **Test isolation** - Use temp dirs for socket tests
3. **Async tests** - Use `#[tokio::test]` for async code
4. **Platform-specific tests** - Use `#[cfg(unix)]` or `#[cfg(windows)]`
5. **Key tag calculation** - Use `crate::dns::dnssec::calculate_key_tag` for RFC 4034 compliant key tags

## Known Code Quality Context

### Clippy and Dead Code Suppressions

Crate-level suppressions in `src/lib.rs`:
- `elided_lifetimes_in_paths` — compiler style preference
- `mismatched_lifetime_syntaxes` — compiler style preference

`#[allow(dead_code)]` annotations: **~72 across ~48 files**. Notable per-module breakdown:
- `src/mesh/transport_*.rs` — ~6 items (reserved protocol handlers)
- `src/mesh/` — ~14 items
- `src/dns/server/` — ~4 items
- `src/waf/` — ~4 items
- `src/tunnel/` — ~5 items
- `src/admin/handlers/` — ~6 items
- `src/overseer/` — ~9 items

Note: Many `#[allow(dead_code)]` annotations are on reserved/future-use code paths within already-shipped modules (e.g., `transport_dns.rs` for future DNS mesh protocol). These are intentional design patterns for future extensibility.

`cargo clippy -- -D warnings` passes clean (previously ~14 non-dead-code warnings, now resolved).

### Build Configuration

`Cargo.toml` uses relaxed version pins (e.g., `"0.11"`).

### Dependency Cleanup (Phase 1 Complete)

The following dead dependencies were removed in Phase 1:
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

## Known Bugs (Quick Reference)

### Remaining Open Issues

| Bug | Location | Impact | Status |
|-----|----------|--------|--------|
| NSEC3 base32 encoding | `src/dns/dnssec_signing.rs:259-282` | Non-standard encoding (uses base32 instead of base32hex) | Open (SHA-1 only in practice) |
| Forwarder no DNSSEC validation | `HickoryResolver` | Forwarder mode doesn't validate; AD bit not propagated | Limitation (documented) |
| `pattern_detector!` macro infinite recursion | `src/waf/attack_detection/detector_common.rs:85-87` | Stack overflow when trait method called | Open |
| WAF empty headers in proxy path | `src/proxy.rs:486` | Header-based WAF rules bypassed | Open |
| SSRF substring matching bypass | `src/waf/attack_detection/ssrf.rs:278-285` | `evil-example.com` passes when `example.com` whitelisted | Open |
| Dynamic worker server stub | `src/worker/mod.rs:261-343` | Placeholder code — drops connections | Open |
| Duplicate AppServer init | `src/worker/unified_server.rs:205-235,858-888` | Second init shadows first | Open |
| WireGuard transport unauthenticated | `src/mesh/transports/wireguard.rs` | Raw UDP with zero authentication | Open |
| DHT query response non-functional | `src/mesh/dht/record_store_sync.rs:657-718` | Returns None immediately without awaiting responses | Open |

### Fixed Issues (Wave 1-7 Complete)

| Bug | Location | Fix |
|-----|----------|-----|
| HTTPS proxy body forwarding | `src/tls/server.rs` | Pass `body_bytes` to upstream; use `send_request_with_body_headers_and_timeout` |
| YARA periodic sync | `src/worker/unified_server.rs` | Call `sync_manager.send_sync_request_to_global()` instead of `drop(msg)` |
| Granian dispatch | `src/app_server/granian.rs` | `forward_request()` now uses built request; AppServer dispatch wired |
| Honeypot mesh wiring | `src/worker/unified_server.rs` | `start_mesh_threat_publishing()` now called after mesh init |
| HTTP body truncation | `src/http/server.rs` | Separated `full_body` from truncated `body_slice` for WAF inspection |
| Dead `build_dnssec_response` | `src/dns/server/dnssec_impl.rs` | Removed dead function |

## Performance Hot Paths

Agents modifying these areas should be aware of performance characteristics:

| Area | Concern | Location |
|------|---------|----------|
| WAF detection | Runs ~20+ checks per request, lock acquisition per request | `src/waf/mod.rs:660-700` |
| Cache lookups | O(1) via `LinkedHashMap`; write lock on LRU update | `src/proxy_cache/store.rs:241` |
| Input normalization | Allocates `String` per request via various transformations | `src/waf/attack_detection/normalizer.rs:20` |
| Rate limiting | `retain` is O(n) per call, 6 sequential calls | `src/waf/ratelimit.rs:122-142` |
| HTTP path sanitization | Allocates `Vec` on every request | `src/proxy.rs:101` |
| Response header filtering | Allocates `Vec` on every proxied response | `src/proxy.rs:147-159` |
| SSRF detection | Calls `.to_lowercase()` multiple times on same input | `src/waf/attack_detection/ssrf.rs` |
| DNS zone store | 64-sharded `RwLock`; prefer single-shard ops over full iteration | `src/dns/server/sharded_store.rs` |

## Module Size Guide

| Module | Lines | Status |
|--------|-------|--------|
| `src/mesh/transport.rs` | ~2,086 | Already split into 11 submodules |
| `src/mesh/protocol_proto_encode.rs` | ~2,024 | Generated protobuf pattern — acceptable |
| `src/mesh/config.rs` | ~1,450 | Split into submodules |
| `src/mesh/protocol.rs` | ~1,196 | Split into submodules |
| `src/dns/server/mod.rs` | ~763 | Split into submodules |
| `src/worker/mod.rs` | ~786 | Split into submodules |
| `src/admin/state.rs` | ~561 | Split into submodules |

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

Seed node certificate fingerprints are managed by `MeshCertManager` in `src/mesh/cert.rs`. On first connection, fingerprints are pinned automatically (Trust On First Use). On subsequent connections, fingerprints are verified in `connect_to_peer()` via `verify_seed_fingerprint()`. Pre-configured fingerprints can be set in TOML config via `pinned_cert_fingerprint` on seed nodes.

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
- `find(Fn(&str, &Zone) -> bool) -> Option<Zone>` — search all shards
- `get_or_create_and_update(&str, FnOnce(&mut Zone))` — entry-or-insert on one shard
- `keys() -> Vec<String>` — collect all zone names (all shards)

When modifying zone access code, prefer single-shard operations (`get`, `insert`, `update_zone`) over full-shard iteration (`for_each`, `keys`). The `Arc<ShardedZoneStore>` replaces the former `Arc<RwLock<HashMap<String, Zone>>>` pattern.

## Session Lessons Learned

### Subagent Verification Required

When using subagents to make code changes:
1. **Always verify the actual code** — subagents may claim a fix was applied but the code still shows the old version
2. **Run compilation checks** — `cargo clippy --lib -- -D warnings` to catch type errors
3. **Run tests** — `cargo test --test integration_test` to verify runtime behavior
4. **Run format check** — `cargo fmt` then `cargo fmt --check` to catch drift

Common failure mode: subagent reports success but code wasn't actually modified, or was modified incorrectly. Always read the actual file content to confirm.

### Moka Cache Migration

When migrating from `LruCache` to `moka::sync::Cache`:
1. `moka::Cache` is already thread-safe — do NOT wrap in `Mutex` or `RwLock`
2. Remove all `.lock()` calls on the cache
3. Use `.get()`, `.insert()` directly (these methods are thread-safe)
4. For TTL: use `.time_to_live()` not `.expire_after()` (latter requires custom `Expiry` trait implementation)
5. For byte-size eviction: use `.max_capacity()` + `.weigher()` where the weigher returns `u32`
6. `max_capacity` expects `u64`, not `usize`

### Role Comparison Best Practices

Always use `role.is_global()` instead of `role == MeshNodeRole::Global` because:
- `MeshNodeRole` is a bitmask (Global=0b010, Edge=0b001, Origin=0b100)
- Composite roles like `GLOBAL_EDGE` (0b011) have the Global bit set
- Direct equality only matches pure roles, missing composite role cases

### RRSIG Timestamp Encoding

RFC 4034 requires 32-bit (u32) timestamps in RRSIG records. When writing:
```rust
// CORRECT:
rrsig.extend_from_slice(&(timestamp as u32).to_be_bytes());

// WRONG (writes 64-bit):
rrsig.extend_from_slice(&timestamp.to_be_bytes());
```

### Plan Verification

When reviewing plan files against the codebase, always verify claims directly. Plans may reference items already fixed, use outdated line numbers, or describe bugs incorrectly. Run `grep`/search for the specific patterns described to confirm they still exist before implementing fixes.

## Remediation Plan

The original remediation plan (Waves 0-6, 185 items) is **complete**. The consolidated improvement plan (`plan.md`) has been updated with ~180 items across 8 waves, organized for parallel sub-agent execution. See `plan.md` for full details.

### Partially Completed Items (from previous waves)
- **Config Schema Generation**: Requires significant refactoring to use schemars derive-based generation (~918 lines of hardcoded schema)
- **Dead Code Cleanup**: Target of <60 annotations not met (~72 current); many reserved protocol modules added

### New Files Added
- `src/admin/handlers/yara_rules.rs` - YARA submission management API
- `src/admin/handlers/plugins.rs` - Plugin metrics and status API
- `src/static_files/file_manager.rs` - File manager core
- `src/http/file_manager.rs` - File manager HTTP handler
- `src/php/mod.rs` - PHP backend support
- `src/cgi/mod.rs` - CGI dispatch
- `src/http/shared_handler.rs` - Shared request handler
- `docs/WASM-ABI.md` - WASM ABI documentation
- `benches/bench_wasm.rs` - WASM benchmarks
- `benches/bench_broadcast.rs` - Broadcast benchmarks

## Admin Panel Architecture Notes

### Config Propagation (Fixed)

Config changes via the admin API now propagate to workers. `MasterConfigReload` handlers implement real reload in `src/worker/mod.rs` and `src/worker/unified_server.rs`. `PUT /config/main` updates in-memory config and broadcasts via `ProcessManager::broadcast_config_reload()`. `POST /config/reload` also broadcasts. Section-specific handlers (HTTP, TLS, security, etc.) call broadcast after persisting.

Worker `common.rs` handler still logs only (full restart required for that worker type). Hot-reloadable vs restart-required field distinction is tracked for future implementation.

### Frontend Orphaned Files

These admin UI files were previously orphaned but are now reachable:

- `admin-ui/src/pages/system_status.rs` — now at Route `/system-status` ✅
- `admin-ui/src/pages/threat_level.rs` — now at Route `/threat-level` ✅

Still orphaned (not declared as module):
- `admin-ui/src/config_docs.rs` (538 lines — field documentation)
