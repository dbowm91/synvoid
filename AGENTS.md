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
let msg = Message::WorkerStarted { ... };
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

## File Naming Conventions

- Source files: `snake_case.rs`
- Test files: `snake_case_test.rs` or in `tests/` directory
- Modules: `mod.rs` for module aggregation

## DNSSEC and RFC 5011

### Trust Anchor Configuration

The `TrustAnchorConfig` struct now supports separate timeout configuration for RFC 5011 state transitions:

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

## Important Notes

1. **Never commit secrets** - Use `.gitignore` for credentials
2. **Test isolation** - Use temp dirs for socket tests
3. **Async tests** - Use `#[tokio::test]` for async code
4. **Platform-specific tests** - Use `#[cfg(unix)]` or `#[cfg(windows)]`
5. **Remediation plan** - See `plan.md` for the full list of known issues and fix priorities (7 phases, 108 items)

## Phase 1 Completion Notes (2026-03-25)

Phase 1 fixed all 12 critical correctness bugs. Key learnings for future agents:

### Body Forwarding Chain

The request body forwarding (1.1) required changes across the full proxy chain:

```
handle_request → forward_request → forward_with_pool → send_single_request
                                                        ↓
                                              send_request_with_body_and_timeout (http_client)
```

Callers of `handle_request_with_cache` (in `src/tls/server.rs` and `src/http/handler.rs`) currently pass `None` for body. When the HTTP request handling layer is updated to extract and pass the request body, these callers should be updated. The `_body` from `req.into_parts()` at `src/http/server.rs:416` is where the body is available.

### Pre-existing Test Failures

`test_ssrf_no_block` (`src/waf/attack_detection/ssrf.rs:301`) was already failing on master before Phase 1. The Aho-Corasick pattern `"192.168."` matches even when `block_private_ips=false`. This is tracked as Phase 1 Follow-up item 1.F4.

### CSS Challenge Behavior Change

Phase 1.2 removed the `path == "/"` guard from CSS challenges. Previously only root path got challenged; now ALL paths (except `/_waf_css_challenge` and `/_waf_assets`) are challenged. This may break API consumers that don't handle cookies. See Phase 1 Follow-up item 1.F3.

### Key Tag RFC Compliance

Both `dnssec.rs:calculate_key_tag` and `trust_anchor.rs:calculate_dnskey_key_tag` now use the RFC 4034 Appendix B algorithm on full DNSKEY RDATA (flags + protocol + algorithm + public_key). The old `dnssec.rs` version computed the tag on raw public_key only, which is incorrect per RFC. These should be consolidated into a shared utility (Phase 1 Follow-up item 1.F5).

### `fetch_update` for Atomic Checked Operations

When preventing integer underflow on atomic counters, use `fetch_update` with `checked_sub` instead of `fetch_sub`:

```rust
// BEFORE (wraps on underflow)
self.current_connections.fetch_sub(1, Ordering::Relaxed);

// AFTER (no-op at zero)
let _ = self.current_connections
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
```

### Auth Store Merge Pattern

When multiple pending stores need persisting, merge them rather than saving only the last one. The pattern used in `src/auth/mod.rs:168-179`:

```rust
fn merge_stores(stores: &[AuthStore]) -> AuthStore {
    let mut merged = stores.last().unwrap().clone();
    for store in stores.iter().take(stores.len() - 1) {
        merged.login_logs.extend(store.login_logs.iter().cloned());
    }
    merged
}
```

Note: this may produce duplicate login_log entries. See Phase 1 Follow-up item 1.F1.

## Phase 2 Completion Notes (2026-03-25)

Phase 2 addressed all 14 security and TLS hardening items. Key learnings for future agents:

### TLS Client Architecture

The HTTP client was refactored from a single `create_http_client_with_config()` to three tiers:

| Function | TLS | Use Case |
|----------|-----|----------|
| `create_http_client()` | `https_or_http()`, native roots + webpki fallback | Internal: honeypot, alerting, worker pool |
| `create_http_client_with_config()` | `https_only()`, native roots + webpki fallback | Default: proxy, TLS server |
| `create_upstream_client()` | Configurable via `UpstreamTlsConfig` | Per-site upstream with `skip_verify`/`allow_plaintext` |

The `build_tls_config()` function centralizes TLS configuration. It loads native root certs via `rustls_native_certs`, falls back to webpki roots if none found, and supports `skip_verify` via a `NoVerifier` struct implementing `rustls::client::danger::ServerCertVerifier`.

**Deferred (2.F1):** `create_upstream_client()` is not yet wired into callers. The proxy, health check, and TLS server should migrate to use it with per-site `UpstreamTlsConfig`.

### Clippy Auto-Fix Side Effects

`cargo clippy --fix --allow-dirty --allow-staged` auto-fixed 544 warnings. Some changes were structural (e.g., collapsing nested `if` statements). Always review auto-fix diffs carefully — one change in `src/waf/rule_feed.rs:336-340` re-indented code in a semantically-correct but confusing way (manually cleaned up).

### IPC Key File-Based Transfer

The IPC session key is now passed via a temp file (`MALUWAF_IPC_KEY_FILE`) instead of an env var. The temp file uses `0600` permissions (Unix only) and is deleted by the worker after reading. Falls back to `MALUWAF_IPC_KEY` env var if file write fails.

The hex-parsing code for reading the key from the file is duplicated from the env var path. Consider extracting a `parse_hex_key(key_hex: &str) -> Option<[u8; 32]>` helper (Phase 3 follow-up).

### IPC Message Validation

The `Message::validate()` function was expanded from 7 validated variants to 30+. Helper functions `check_str`, `check_opt_str`, `check_str_vec` reduce boilerplate. A catch-all `_ => Ok(())` still exists for future variants — new variants with string fields should add explicit validation arms.

### 501 for Stub Endpoints

Six admin endpoints that returned success without doing anything now return `501 NOT_IMPLEMENTED` with `tracing::warn!` logs. This is a breaking API change — clients calling these endpoints will receive HTTP 501 instead of 200.

## Phase 3 Completion Notes (2026-03-25)

Phase 3 addressed error handling, unsafe documentation, and dead code. Key learnings for future agents:

### Centralized Error Type

Created `src/error.rs` with `WafError` enum and `WafResult<T>`. The enum covers common error categories (I/O, JSON, IPC, config, crypto, upstream) with `From` impls for `std::io::Error`, `serde_json::Error`, `String`, and `&str`. A `WafErrorExt` trait provides `.waf_internal()`, `.waf_ipc()`, `.waf_config()`, `.waf_upstream()` convenience methods for mapping any error with context.

**Usage pattern for new code:**
```rust
use maluwaf::error::{WafError, WafResult, WafErrorExt};

fn do_thing() -> WafResult<()> {
    let data = std::fs::read("file").waf_internal("reading config")?;
    Ok(())
}
```

### Unwrap/Expect Audit

The plan cited 580 unwrap/expect calls, but ~540 were in test code (acceptable). Only ~44 were in non-test production code. Fixes applied:

| Category | Count | Fix Pattern |
|----------|-------|-------------|
| `duration_since(UNIX_EPOCH).unwrap()` | 9 | `.unwrap_or_default()` — clock before epoch returns 0 |
| Guarded `as_ref().unwrap()` | 4 | `.expect("checked is_some above")` — documents the guard |
| Response builder fallback | 12 | `.expect("building static 500 response should never fail")` |
| Hardcoded literal parse | 5 | `.expect("valid socket address literal")` inside `unwrap_or_else` |
| `RwLock::read/write().unwrap()` | 3 | Switched to `parking_lot::RwLock` (no Result return) |
| `Mutex::lock().unwrap()` | 4 | Switched to `parking_lot::Mutex` (no Result return) |

**Pattern: `duration_since(UNIX_EPOCH).unwrap()`**
```rust
// BEFORE (panics if system clock is before 1970)
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

// AFTER (returns 0 for pathological clock)
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
```

**Pattern: Mutex/RwLock in sync contexts**
```rust
// BEFORE (std::sync::Mutex — can panic on poisoned lock)
use std::sync::Mutex;
let guard = self.data.lock().unwrap();

// AFTER (parking_lot::Mutex — no poisoning, no Result)
use parking_lot::Mutex;
let guard = self.data.lock();
```

### Unsafe Block Documentation

Added `// SAFETY:` comments to 7 previously undocumented unsafe blocks:
- `src/worker/mod.rs` — 5 blocks (Windows named pipe IPC: CreateNamedPipeW, ConnectNamedPipe, GetLastError, CloseHandle, from_raw_handle)
- `src/platform/windows_impl.rs` — 2 blocks (CloseHandle, from_raw_parts for WSAPROTOCOL_INFOW)

Added `# Safety` doc comments to 2 `unsafe fn` declarations in `src/process/socket_fd.rs` (non-Unix stubs).

**Current unsafe documentation status:** ~95% of unsafe blocks now have SAFETY comments. Remaining undocumented items are `unsafe fn` with `# Safety` doc on the signature (standard Rust convention).

### Dead Code Removal

Removed crate-level `#![allow(dead_code)]` from `src/lib.rs` and module-level `#![allow(dead_code)]` from `src/worker/mod.rs`. This revealed 12 genuinely unused items, which were given targeted `#[allow(dead_code)]` annotations with descriptive context. Each was evaluated:
- Items conditionally compiled (`#[cfg(unix)]`, `#[cfg(windows)]`) — kept with allow
- Items for future use (RSA key generation helpers) — kept with allow
- Items in API completeness (RingBuffer::with_capacity) — kept with allow

### Pre-existing Clippy Warning Increase

Removing the `dead_code` suppression increased clippy warnings from ~107 to ~156. The new warnings are primarily "field is never read" (previously suppressed by the crate-level allow). These are deferred to later phases as they indicate fields that may be written but not yet read by the codebase.

## Known Code Quality Context

### Clippy and Dead Code Suppressions

Phase 2.1 removed `#![allow(clippy::all)]` from `src/lib.rs`. Phase 3.4 removed `#![allow(dead_code)]` from both `src/lib.rs` and `src/worker/mod.rs`. Current crate-level suppressions (see `src/lib.rs:1-7`):

- `elided_lifetimes_in_paths` — compiler style preference
- `mismatched_lifetime_syntaxes` — compiler style preference
- `clippy::too_many_arguments` — deferred to Phase 6 (builder/config struct refactoring)
- `clippy::await_holding_lock` — deferred to Phase 4.5 (async mutex standardization)

Remaining per-item `#[allow(dead_code)]` on specific functions/types:
- `src/worker/mod.rs` — 5 items (MinifierCache, get_content_type, get_compressed_content, ListenerType, send_compressed_error)
- `src/waf/ratelimit.rs` — 2 items (IpRateLimitState::new, RingBuffer::with_capacity)
- `src/dns/cache.rs` — 2 items (skip_name, detect_dnssec_signed)
- `src/dns/dnssec.rs` — 3 items (extract_rsa_modulus, len_of_der_length, decode_der_length)
- `src/mesh/` — ~13 items (item-level, gated on feature/platform)
- `src/dns/server.rs` — ~10 items (item-level)

`cargo clippy` currently produces ~156 warnings (up from 107 after removing dead_code suppression, which revealed "field is never read" warnings). These are incremental quality issues that don't affect correctness.

### Build Configuration

Phase 2.2 moved `target-dir = "target/fuzz"` from `.cargo/config.toml` to `fuzz/.cargo/config.toml`. Normal builds now use the default `target/` directory.

`Cargo.toml` still uses many exact patch version pins (e.g., `"0.11.11"` instead of `"0.11"`). This prevents automatic security updates.

## Known Bugs (Quick Reference)

Agents working on these areas should be aware of these issues. See `plan.md` for full details and fixes.

> **Phase 1 bugs (1.1-1.12) are FIXED.** The "Critical Correctness" table below lists
> only the remaining known bugs from later phases. See `plan.md` Phase 1 Follow-ups for
> minor items discovered during Phase 1 review (auth log dedup, SSRF test, CSS exemptions).

### Critical Correctness (Remaining)

| Bug | Location | Impact |
|-----|----------|--------|
| `get_or_fetch` never calls fetch | `src/proxy_cache/store.rs:303-313` | `_fetch` callback never invoked |

### Security

| Bug | Location | Impact |
|-----|----------|--------|
| TLS: `skip_verify` not wired | `src/http_client/mod.rs:66` | Field defined but `create_upstream_client()` not yet called by proxy (Phase 2.F1) |

### DNS / RFC Compliance

| Bug | Location | Impact |
|-----|----------|--------|
| Trust anchor save errors silently ignored | `src/dns/trust_anchor.rs:676-678` | `let _ = self.save_anchors(...)` |

### Dead Code (Not Compiled)

`src/http/handler.rs` (1,657 lines) and `src/http/range.rs` (194 lines) exist but are NOT in the module tree (`src/http/mod.rs` does not declare them). They contain a compile error (`site_request_key` undefined at `handler.rs:433`) and synchronous filesystem I/O in async functions. Do not reference these files — they are effectively dead.

## Performance Hot Paths

Agents modifying these areas should be aware of performance characteristics:

| Area | Concern | Location |
|------|---------|----------|
| WAF detection | Runs ~20+ checks per request, lock acquisition per request | `src/waf/mod.rs:667-1056` |
| Cache lookups | O(n) `VecDeque::retain` on every operation; write lock on read | `src/proxy_cache/store.rs:225,241` |
| Input normalization | Always clones input string unnecessarily | `src/waf/normalizer.rs:38` |
| Rate limiting | `retain` is O(n) per call, 6 sequential calls | `src/waf/ratelimit.rs:122-142` |
| HTTP path sanitization | Allocates `String` on every request | `src/proxy.rs:94` |
| Response header filtering | Allocates `Vec` on every proxied response | `src/proxy.rs:151-158` |

## Code Duplication Patterns

These patterns repeat and should be consolidated (see `plan.md` Phase 6.3):

- `reload_attack_detector` repeats the same "check category, extend patterns" block 10 times (`src/waf/mod.rs:458-510`)
- `get_custom_patterns_for_category`, `update_patterns_for_category`, `has_custom_patterns` have identical match arms (`src/waf/rule_feed.rs:104-170`)
- `convert_rules_to_ipc_patterns` is 100 lines of repetitive matching (`src/waf/rule_feed.rs:555-656`)
- Error page status text mapping repeated 3 times (`src/waf/endpoints.rs:415-494`)

## Module Size Guide

Large modules that need splitting (see `plan.md` Phase 6.5):

| Module | Lines | Notes |
|--------|-------|-------|
| `src/mesh/transport.rs` | 6,464 | God object — split by message handler category |
| `src/dns/server.rs` | 4,500+ | Extract query handler, zone manager, rate limiter |
| `src/dns/mesh_sync.rs` | 1,975 | Split into registry, verification, health |
| `src/worker/mod.rs` | 1,566 | Extract connection handling, drain state |
| `tests/integration_test.rs` | 2,012 | Mixes DNS, IPC, config tests — split per module |
