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

## Known Code Quality Context

### Clippy and Dead Code Suppressions

These blanket suppressions exist and should be removed (see `plan.md` Phase 2.1, 3.4):

- `src/lib.rs:1` — `#![allow(clippy::all)]` suppresses ALL clippy lints
- `src/worker/mod.rs:1` — `#![allow(dead_code)]`
- ~22 files in `src/mesh/` — `#![allow(dead_code)]`
- ~10 items in `src/dns/server.rs` — `#[allow(dead_code)]`

`cargo clippy -- -D warnings` currently passes because of these suppressions. When removing them, fix warnings incrementally per-module.

### Build Configuration

- `.cargo/config.toml:2` sets `target-dir = "target/fuzz"` which affects ALL cargo commands globally. This is likely unintended — normal builds should use `target/`.
- `Cargo.toml` uses many exact patch version pins (e.g., `"0.11.11"` instead of `"0.11"`). This prevents automatic security updates.

## Known Bugs (Quick Reference)

Agents working on these areas should be aware of these issues. See `plan.md` for full details and fixes.

> **Phase 1 bugs (1.1-1.12) are FIXED.** The "Critical Correctness" table below lists
> only the remaining known bugs from later phases. See `plan.md` Phase 1 Follow-ups for
> minor items discovered during Phase 1 review (auth log dedup, SSRF test, CSS exemptions).

### Critical Correctness (Remaining)

| Bug | Location | Impact |
|-----|----------|--------|
| Embedded key is placeholder | `src/waf/rule_feed.rs:10` | Rule signature verification always fails |
| `get_or_fetch` never calls fetch | `src/proxy_cache/store.rs:303-313` | `_fetch` callback never invoked |

### Security

| Bug | Location | Impact |
|-----|----------|--------|
| CORS wildcard allowed in admin API | `src/admin/mod.rs:36` | `origin == "*"` accepts any origin |
| IPC key passed via environment variable | `src/process/manager.rs:448-451` | Readable from `/proc/<pid>/environ` |
| TLS: plaintext HTTP to upstreams by default | `src/http/http_client/mod.rs:99-104` | `https_or_http()` allows unencrypted |
| TLS: panic on missing root certs | `src/http/http_client/mod.rs:100` | `.with_native_roots().unwrap()` |
| IPC deserialization `.unwrap()` on malformed data | `src/process/ipc.rs:1080-1295` | Malformed messages crash process |

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
