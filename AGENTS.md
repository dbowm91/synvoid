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

`#[allow(dead_code)]` annotations: **137 across 75 files** (verified via grep). Notable per-module breakdown:
- `src/worker/mod.rs` — 4 items (MinifierCache, get_content_type, get_compressed_content, ListenerType)
- `src/waf/ratelimit.rs` — 2 items
- `src/dns/cache.rs` — 2 items (skip_name, detect_dnssec_signed)
- `src/dns/dnssec.rs` — 3 items (extract_rsa_modulus, len_of_der_length, decode_der_length)
- `src/mesh/` — ~29 items (90+ dead code warnings per clippy)
- `src/dns/server/` — ~10 items

`cargo clippy` produces ~93 warnings (pre-existing categories, incremental quality issues).

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

`src/error.rs` defines `WafError`, `WafResult`, and `WafErrorExt` — **all are completely dead code**. Zero production usage outside `error.rs` itself. Every other module uses `anyhow`, `Box<dyn Error>` (16 call sites), or custom error types.

### Duplicate Timestamp Utility

7 duplicate `current_timestamp()` definitions exist:
- `src/waf/probe_tracker.rs:446`
- `src/process/ipc.rs:1311`
- `src/mesh/dht/stake.rs:533`
- `src/overseer/state.rs:148`
- `src/mesh/transports/manager.rs:32`
- `src/captcha/mod.rs:185`
- `src/utils.rs:414` (canonical)

Use the `utils.rs` version and remove the rest.

### 7 Duplicate `default_true()` Functions

Consolidate into 1 canonical version in `src/config/defaults.rs`. Found in site.rs, security.rs, proxy.rs, logging.rs, and others.

## Known Bugs (Quick Reference)

### Critical Correctness

| Bug | Location | Impact |
|-----|----------|--------|
| BCRYPT_COST = 4 | `src/admin/auth.rs:9` | Trivially brute-forceable auth tokens |
| Auth timing attack | `src/auth/mod.rs:370-432` | Username enumeration: wrong-password for existing user returns ~200ms faster than non-existent user |
| IPC lock contention | `src/worker/mod.rs` (3 competing tasks) | Deadlock risk under load |

### ~~Plugin ABI Mismatch~~ ✅ FIXED (Wave 4)

### Security

| Bug | Location | Impact |
|-----|----------|--------|
| TLS skip_verify | `src/http_client/mod.rs:201-211` | No verification of upstream certificates |
| Plaintext bcrypt fallback | `src/admin/auth.rs:15-36` | If bcrypt fails, token stored as plaintext |
| IPC key fallback to env var | `src/process/manager.rs:446-458` | Key visible in /proc if temp file creation fails |
| CORS wildcard not enforced at site level | `src/http/headers.rs` | Only admin API rejects `allow_origin: "*"` |
| Token in validation error | `src/config/admin.rs:105-109` | Generated token appears in error messages |

### DNS / RFC Compliance

| Bug | Location | Impact |
|-----|----------|--------|
| NSEC3 salt application | `dnssec.rs:1324` | Salt applied incorrectly per RFC 5155 §5 |
| NSEC3 base32 padding | `dnssec.rs:1432` | Includes padding chars that should be stripped |
| NSEC3 owner name missing hash-length byte | `dnssec.rs:1404` | Violates RFC 5155 §3.2 |
| DNSKEY publishes KSK only | `dnssec_impl.rs:35` | Missing ZSK in DNSKEY RRset |
| CDS uses wrong type | `dnssec_impl.rs:74` | Type 43 (DS) instead of 59 (CDS) |
| SRV canonical_rdata incomplete | `dnssec.rs:1520` | Missing weight/port/target fields |
| ARCOUNT off by one | `response.rs:30` | OPT record appends incorrectly |
| MX record trailing null | `response.rs:135` | Missing null byte after exchange name |
| Forwarder no DNSSEC validation | `HickoryResolver` | Forwarder mode doesn't validate; AD bit not propagated |

### DHT

| Bug | Location | Impact |
|-----|----------|--------|
| Unbounded PoW nonce loop | `node_id.rs:138` | Can hang on startup if no valid nonce found |
| Duplicate peers in lookup | `query.rs:50` | Same peer queried multiple times |
| PoW not persisted | `table.rs:539` | Contact restored without verifying PoW |
| XOR distance uses first byte only | `geo_distance.rs:117` | Poor ranking granularity for IPv6 |

### Dead Code (Removed)

`src/http/handler.rs` (1,661 lines) and `src/http/range.rs` (194 lines) were deleted in Phase 1 — they were never in the module tree and had compile errors.

### ~~Plugin ABI Mismatch~~ ✅ FIXED (Wave 4)

~~`examples/dynamic-plugin-example/src/lib.rs:23` exports `rustwaf_abi_version` but `src/plugin/axum_loader.rs:110` looks for `maluwaf_abi_version`. Loading the example plugin will fail with `SymbolNotFound`.~~ Fixed: example plugin now exports `maluwaf_abi_version`.

## Performance Hot Paths

Agents modifying these areas should be aware of performance characteristics:

| Area | Concern | Location |
|------|---------|----------|
| WAF detection | Runs ~20+ checks per request, lock acquisition per request | `src/waf/mod.rs:660-700` |
| Cache lookups | O(n) `VecDeque::position/remove` per operation; write lock on LRU update | `src/proxy_cache/store.rs:241` |
| Input normalization | Allocates `String` per request via various transformations | `src/waf/attack_detection/normalizer.rs:20` |
| Rate limiting | `retain` is O(n) per call, 6 sequential calls | `src/waf/ratelimit.rs:122-142` |
| HTTP path sanitization | Allocates `Vec` on every request | `src/proxy.rs:101` |
| Response header filtering | Allocates `Vec` on every proxied response | `src/proxy.rs:147-159` |
| SSRF detection | Calls `.to_lowercase()` 4+ times on same input | `src/waf/attack_detection/ssrf.rs` |

## Module Size Guide

| Module | Lines | Status |
|--------|-------|--------|
| `src/mesh/protocol_proto_encode.rs` | ~1,989 | Proto conversion (generated pattern, acceptable) |
| `src/dns/dnssec.rs` | ~2,152 | Above 1,500 but below threshold |
| `src/mesh/transport.rs` | ~1,897 | Split into submodules |
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

### ACME Stub

`src/tls/acme.rs` is a stub returning `AcmeError::UseExternalClient`. Config fields exist but no actual ACME protocol implementation. See Phase 7 in `plans/fullplan.md`.

### TLS Passthrough

The `tls_passthrough` field in `src/tunnel/quic/messages.rs` and `src/config/tunnel.rs` is dead code — logged and ignored. See Phase 7.3 in `plans/fullplan.md`.

### Cert Distribution (Planned)

The mesh layer will support origin→edge TLS certificate distribution via 3 new messages (`SiteTlsCertSync`, `SiteTlsCertRequest`, `SiteTlsCertResponse`) in `src/mesh/protocol.rs`. Private keys are encrypted with AES-256-GCM using a per-site key derived via HKDF from the mesh session key. See Phase 7.2 in `plans/fullplan.md`.

### IPC Session Key

The IPC session key is passed via a temp file (`MALUWAF_IPC_KEY_FILE`) instead of an env var. The temp file uses `0600` permissions (Unix only) and is deleted by the worker after reading. Falls back to `MALUWAF_IPC_KEY` env var if file write fails.

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

## Remediation Plans

See `plans/fullplan.md` for the consolidated 33-plan master plan (12 phases) with parallel execution guidance.
