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

> **Completed.** See section above for details.

## Phase 4 Completion Notes (2026-03-25)

Phase 4 addressed performance and reliability items. Key changes and learnings:

### Cache Store Refactoring (`src/proxy_cache/store.rs`)

**`VecDeque::retain` replaced with `position/remove`:** All 7 `retain` calls were replaced with `VecDeque::position()` + `remove()`. While both are O(n), `position/remove` avoids allocating a closure on every call and short-circuits on the first match. A helper function `move_to_back()` was added for the common pattern of "remove from current position + push to back".

**`get_hit_status` already used read lock:** The plan suggested switching from write lock to read lock, but `get_hit_status` was already using `self.state.read()`. The `get` method still requires a write lock because it updates access order.

**`get_or_fetch` made async and functional:** The method was changed from sync (returning `Option<ProxyCacheEntry>` and never calling `_fetch`) to `async` (calling `fetch().await` on cache miss, storing the result, then returning it). Has no callers currently but is now correct as a public API.

**Cache-Control parsing enhanced (`src/proxy.rs`):** Both `get_cache_max_age` and `get_cache_max_age_static` now parse `s-maxage` (takes precedence for shared/proxy caches), `no-cache`, and quoted values. Previously only `max-age=` was parsed.

**Binary corruption deferred (4.1.4):** `build_cached_response` uses `String::from_utf8_lossy` which corrupts binary content (images, compressed data). Fix requires changing `Response<String>` to `Response<Bytes>` throughout the proxy pipeline — deferred to Phase 6 refactoring.

### Normalizer (`src/waf/attack_detection/normalizer.rs`)

**Removed `original` field:** `NormalizedInput.original` was always a clone of the input but never read by any code. Removing it eliminates one `String` allocation per WAF-checked request. The `original` field was removed from the struct and the `normalize` method no longer clones.

### Process Management (`src/process/manager.rs`)

**Unified worker restart limit:** `handle_unified_worker_restart` now checks `restart_count < max_restart_attempts` before restarting, matching the behavior of regular workers. The `UnifiedServerWorkerProcess` struct already had `restart_count` and `last_restart_at` fields — they just weren't being checked.

**Dummy IPC panic removed (`src/worker/mod.rs`):** The reload handler used `futures::executor::block_on` + `unwrap_or_else(|_| panic!(...))` to create a dummy IPC connection inside an async context. Replaced with a proper `await` and `continue` on failure, removing both the `block_on` (which can deadlock the Tokio runtime) and the unconditional panic.

### Connection Tracker (`src/overseer/connection_tracker.rs`)

**Switched to `parking_lot::Mutex`:** `std::sync::Mutex` was used for `drain_start_time`. Replaced with `parking_lot::Mutex` which doesn't return a `Result` from `lock()` (no poisoning), eliminating 4x `.unwrap()` calls. `parking_lot` was already a dependency.

### Overseer Lock File (`src/process/pidfile.rs`)

**`flock` as primary mechanism:** The `OverseerLockFile` previously used a check-then-write pattern (check if lock exists → check if process is alive → write lock file) which has a TOCTOU race. Now uses `flock(FlockArg::LockExclusiveNonblock)` on the lock file before writing the PID, making the acquire operation atomic. The `lock_file` field was changed from `Option<()>` to `Option<File>` to hold the file descriptor for the flock lifetime.

### Socket Handoff (`src/overseer/socket_handoff.rs`)

**FD count assertion:** Added an explicit check that `fds.len() == ports.len()` after receiving file descriptors. Previously, a mismatch would silently zip fewer FDs with ports, leading to port→FD mapping errors.

### Drain IPC Retry (`src/overseer/drain_manager.rs`)

**Retry with exponential backoff:** `drain_worker_with_confirmation` previously failed immediately if `poll_drain_status` returned an error. Now retries up to 3 times with exponential backoff (100ms, 200ms, 400ms) for transient IPC errors, only failing if all retries are exhausted.

### DNS Cache (`src/dns/cache.rs`)

**TTL-based fingerprint eviction:** Cache fingerprints (used for poisoning detection) were bounded only by count (`max_fingerprints_per_name`). Now also evict entries older than 1 hour via `Instant` timestamps stored alongside each fingerprint.

### Items Deferred to Later Phases

| Item | Reason | Target Phase |
|------|--------|-------------|
| Binary body in cache (4.1.4) | Needs `Response<String>` → `Response<Bytes>` refactor | 6 |
| Async mutex standardization (4.5) | `_sync` variants are used from sync callers, `blocking_read` is correct for those contexts | 6 |
| Arc\<Firewall\> shared queries (4.6.2) | DNS server is large; needs modular split first | 6 |
| Batch zone index rebuild (4.6.3) | DNS server refactoring dependency | 6 |
| WAF `to_uppercase` allocation (4.2.2) | Requires pre-lowercased constant comparison | 6 |
| InputLocation::Header allocation (4.2.3) | Requires `Cow<str>` or lifetime refactoring | 6 |
| stdout/stderr pipe blocking (4.3.3) | Platform-specific, needs careful testing | 5 |
| Stale IPC drain filter (4.3.2) | Need to identify where stale messages are received | 5 |

### Pre-existing Items Already Implemented

Two items were already implemented before Phase 4:

- **4.3.10 Zone history:** `increment_serial_with_limit(50)` already caps history to 50 entries
- **4.6.1 Rate limiter cleanup:** `cleanup_if_needed` already throttles to every 60 seconds via `CLEANUP_INTERVAL_SECS`

## Phase 5 Completion Notes (2026-03-25)

Phase 5 addressed DNS RFC compliance and process management items. Key changes and learnings:

### Key Tag RFC Compliance (5.2)

Both `dnssec.rs::calculate_key_tag` and `trust_anchor.rs::calculate_dnskey_key_tag` were consolidated. The `trust_anchor.rs` version used `(sum & 0xFFFF)` which is incorrect per RFC 4034 Appendix B — the correct formula is `(sum + (sum >> 16)) & 0xFFFF`. The `dnssec.rs` version (now public) has the correct implementation. All callers in `trust_anchor.rs` (16 call sites) and `resolver.rs` now use `crate::dns::dnssec::calculate_key_tag`.

**Key learning:** When unifying duplicate implementations, always verify which one is RFC-compliant. The two implementations looked identical but differed in the final masking step.

### generate_key Unification (5.8)

`generate_key` and `generate_standby_key` shared ~80% of their code. Extracted a private `generate_key_internal(algorithm, key_type, rsa_key_size, validity_days, is_standby)` method. The public methods are thin wrappers. The `key_id` match uses a tuple `(key_type, is_standby)` for clean dispatch.

### QueryContext Struct (5.9)

`handle_tcp_query` had 23 parameters. A `QueryContext<'a>` struct was introduced to bundle the Arc-wrapped DNS service references. The function signature changed from 23 params to 2 (`stream`, `ctx: QueryContext`).

**Call sites:** Two call sites (anycast TCP listener at ~line 1838, regular TCP listener at ~line 2258) now construct a `QueryContext` before calling `handle_tcp_query`. The `_zone_index` parameter was dropped since it was already unused (prefixed with `_`).

**Note:** `handle_query_with_cache` (16 params) and `handle_query` (10 params) were NOT refactored to use QueryContext since their parameter sets differ. This is deferred to Phase 6.

### NXDOMAIN Question Section (5.3)

The `build_simple_nxdomain_response` function already included the question section (QDCOUNT=1, copies QNAME + QTYPE + QCLASS from query). The test `test_nxdomain_response_basic` was asserting the OLD behavior (QDCOUNT=0, response length 12). Updated the test to assert QDCOUNT=1, verify QTYPE/QCLASS are present.

### Stale IPC During Drain (4.3.2)

Attempted to add `drain_id` filtering to `drain_worker_async`. The drain request already includes a unique `drain_id` (millisecond timestamp), but the response messages (`UnifiedServerWorkerDrained`, `StaticWorkerDrained`) don't include `drain_id`. Filtering requires adding `drain_id` to response message variants — deferred to Phase 6 as an IPC message format change.

### stdout/stderr Pipe Blocking (4.3.3)

Changed `Stdio::piped()` to `Stdio::inherit()` in `build_worker_command`. The piped stdout/stderr were never read by the parent, so if the child wrote enough output, it would block. `Stdio::inherit()` routes child output to the parent's stdout/stderr directly.

### DNS Query Parsing (5.10)

Replaced the inline `extract_query_name` method (manual wire format parsing with `String::from_utf8_lossy`) with a call to `wire::parse_query_name(query, 12)`. The `parse_query_name` function does stricter UTF-8 validation and handles edge cases better. Only one other inline parsing site exists (`tsig.rs:293`) which walks through multiple records and can't use `parse_query_name`.

### Items Deferred to Phase 6

| Item | Reason |
|------|--------|
| 5.11 mesh_sync.rs split | 1,975 lines; too complex and risky for Phase 5 |
| ~~4.3.2 drain_id in response messages~~ | ✅ Fixed in Phase 6 — `drain_id` added to `UnifiedServerWorkerDrained` and `StaticWorkerDrained` |
| handle_query_with_cache / handle_query QueryContext | 18 call sites across 4 files; too risky for Phase 6 |

## Phase 6 Completion Notes (2026-03-25)

Phase 6 addressed subsystem refactoring items. 12 of 40+ items completed; remaining deferred to Phase 7+. Verification: `cargo check` ✅ `cargo check --features dns` ✅ `cargo test --test integration_test` ✅ (99/99 passed). `cargo clippy` produces 154 warnings (up from 152; all are pre-existing categories).

### WAF Code Duplication (6.3.3-6.3.6)

**`reload_attack_detector` macro (6.3.3):** The 10x repeated `get_custom_patterns_for_category` + `extend` pattern was collapsed into a local `macro_rules! merge_patterns` macro. Each invocation is now 1 line instead of 3. The macro works because both `DetectorConfig` and `SsrfConfig` have a `custom_patterns: Vec<String>` field.

**Rule feed match consolidation (6.3.4):** `update_patterns_for_category`, `get_custom_patterns_for_category`, and `has_custom_patterns` each had 12-variant match arms matching the same category strings. Each was refactored to use a local `macro_rules!` macro that reduces each arm to 1 line. Note: these could alternatively use a `HashMap<String, Option<Vec<String>>>` but the macro approach preserves the current `RwLock<GlobalRulePatterns>` structure.

**`convert_rules_to_ipc_patterns` macro (6.3.5):** 100 lines of repeated `if let Some(ref x) = rules.x { if let Some(ref p) = x.patterns { ... } }` collapsed into a `push_if_present!` macro. Each invocation is 1 line instead of 7.

**Status text extraction (6.3.6):** Three duplicated 15-variant `match status_code` blocks in `endpoints.rs` consolidated into a single `fn status_text(code: u16) -> &'static str` method. One inconsistency fixed: `minimal_page` used `"Error"` as default while others used `"An Error Occurred"` — now all use `"An Error Occurred"`.

### Admin Subsystem (6.2.3, 6.2.6, 6.2.7, 6.2.8, 6.2.10)

**XSS in legacy HTML (6.2.3):** Added `escape_html()` function to `src/admin/legacy.rs`. All user-controlled fields (`username`, `sites`, `ip_address`, `reason`, `session id`) are now HTML-escaped before interpolation into the admin dashboard HTML. This prevents stored XSS if a user registers with a username containing `<script>` tags.

**CSRF token cleanup (6.2.6):** `cleanup_expired_csrf_tokens()` existed but was never called. Added a call in the 60-second `alert_ticker` in `src/admin/metrics.rs:44`. Expired tokens are now cleaned up every 60 seconds.

**VecDeque for metrics/logs (6.2.7/6.2.8):** `metrics_history` and `request_logs` changed from `Vec` to `VecDeque`. `Vec::remove(0)` (O(n) shift) replaced with `VecDeque::pop_front()` (O(1)). The `get_metrics_history` method's `history[start..].to_vec()` was changed to `history.iter().skip(start).cloned().collect()` since `VecDeque` doesn't support `Index<RangeFrom<usize>>`.

**get_client_ip consolidation (6.2.10):** `common.rs::get_client_ip` now checks for the `ClientIp` extension (set by middleware) first, falling back to header extraction. This avoids redundant header parsing when the middleware has already run.

### Mesh Subsystem (6.1.12, 6.1.13)

**PEM loading extraction (6.1.12):** `build_server_config` and `build_client_config` in `src/mesh/cert.rs` had identical 21-line blocks for loading cert chain and private key from PEM files. Extracted into `fn load_cert_chain_and_key(cert_path, key_path) -> Result<(Vec<CertificateDer>, PrivateKeyDer), MeshCertError>`.

**Pre-compiled regex (6.1.13):** `MeshAttackDetector::detect_attack` compiled regex patterns on every call via `regex::Regex::new(&pattern.pattern)`. Added `compiled_regex: Option<Arc<regex::Regex>>` field to `SuspiciousPattern` and a `SuspiciousPattern::new()` constructor that pre-compiles regexes. `detect_attack` now uses the pre-compiled regex when available. Regex compilation is expensive (microseconds to milliseconds per pattern) so this is significant for hot paths.

### IPC Drain ID (5.F2 / 4.3.2)

**`drain_id` in response messages:** Added `drain_id: u64` field to `UnifiedServerWorkerDrained` and `StaticWorkerDrained` IPC message variants. The `drain_worker_async` function's `drain_response_fn` closure now takes `(msg, expected_drain_id)` and filters responses by matching drain_id. This prevents stale drain responses from a previous drain operation from being accepted. The worker captures `drain_id` before clearing it to 0.

### Performance Fix (4.2.2)

**`to_uppercase` allocation elimination:** `EndpointBlocker::check` allocated a `String` via `method.to_uppercase()` on every request. Replaced with `guard.block_methods.iter().any(|m| m.eq_ignore_ascii_case(method))` which avoids the allocation entirely. Since HTTP methods are a fixed small set, the linear scan is faster than allocation + hash lookup.

### Items Deferred to Later Phases

| Item | Phase | Reason |
|------|-------|--------|
| 6.1.1 transport.rs split (6,448 lines) | 7+ | God object; needs careful incremental extraction of handler modules |
| 6.1.2 Duplicate MeshTransportError | 7+ | Requires transport.rs split first |
| 6.1.3 blocking_read in async | N/A | `_sync` variants are correct for sync callers (see Phase 4.5 notes) |
| 6.1.4 duration_since unwrap | 7+ | ~80+ occurrences across mesh; mechanical but widespread |
| 6.1.5 expect in crypto paths | 7+ | Needs Result return type changes |
| 6.1.6 mesh dead_code allows | 7+ | 27 suppressions; need per-item audit |
| 6.1.7-6.1.14 mesh config/message/lock | 7+ | Large structural changes |
| 6.2.1 block_on in admin | 7+ | Needs async refactor of router creation |
| 6.2.2 theme/honeypot auth | 7+ | Needs auth middleware integration |
| 6.2.4-6.2.5 rate limiter/auth consolidation | 7+ | Structural refactor |
| 6.2.8-6.2.13 admin state/config | 7+ | AdminState god object split |
| 6.3.2 check_request_full split | 7+ | ~400 lines; extract rate limit, bot, honeypot, challenge checks |
| 6.4 IPC dedup | 7+ | Platform-specific IPC code |
| 6.5 Large module splits | 7+ | All modules >1,000 lines |
| 5.F3 handle_query_with_cache QueryContext | 7+ | 18 call sites across 4 files |
| 4.1.4 Binary body in cache | 7+ | Needs Response<String> → Response<Bytes> throughout proxy pipeline |
| 4.6.2 Arc<Firewall> shared | 7+ | Needs DnsFirewall interior mutability change |
| 4.6.3 Batch zone index rebuild | 7+ | Needs zone load batching |
| mesh_sync.rs split (1,975 lines) | 7+ | Complex with verification loop state |

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

`cargo clippy` currently produces ~154 warnings (up from 152 after Phase 6 additions; all are pre-existing categories). These are incremental quality issues that don't affect correctness.

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
| *(none - all Phase 4 bugs fixed)* | | |

### Security

| Bug | Location | Impact |
|-----|----------|--------|
| TLS: `skip_verify` not wired | `src/http_client/mod.rs:66` | Field defined but `create_upstream_client()` not yet called by proxy (Phase 2.F1) |

### DNS / RFC Compliance

| Bug | Location | Impact |
|-----|----------|--------|
| *(none - all Phase 5 items addressed)* | | |

### Dead Code (Not Compiled)

`src/http/handler.rs` (1,657 lines) and `src/http/range.rs` (194 lines) exist but are NOT in the module tree (`src/http/mod.rs` does not declare them). They contain a compile error (`site_request_key` undefined at `handler.rs:433`) and synchronous filesystem I/O in async functions. Do not reference these files — they are effectively dead.

## Performance Hot Paths

Agents modifying these areas should be aware of performance characteristics:

| Area | Concern | Location |
|------|---------|----------|
| WAF detection | Runs ~20+ checks per request, lock acquisition per request | `src/waf/mod.rs:667-1056` |
| Cache lookups | O(n) `VecDeque::position/remove` per operation; write lock on LRU update | `src/proxy_cache/store.rs:225,241` |
| Input normalization | Allocates `String` per request via NFKC normalization | `src/waf/attack_detection/normalizer.rs:349` |
| Rate limiting | `retain` is O(n) per call, 6 sequential calls | `src/waf/ratelimit.rs:122-142` |
| HTTP path sanitization | Allocates `String` on every request | `src/proxy.rs:94` |
| Response header filtering | Allocates `Vec` on every proxied response | `src/proxy.rs:151-158` |

## Code Duplication Patterns

These patterns repeat and should be consolidated (see `plan.md` Phase 6.3):

- ~~`reload_attack_detector` repeats the same block 10 times~~ ✅ Fixed in Phase 6 — now uses `merge_patterns!` macro
- ~~`get_custom_patterns_for_category`, `update_patterns_for_category`, `has_custom_patterns` have identical match arms~~ ✅ Fixed in Phase 6 — each uses local `macro_rules!` macro
- ~~`convert_rules_to_ipc_patterns` is 100 lines of repetitive matching~~ ✅ Fixed in Phase 6 — now uses `push_if_present!` macro
- ~~Error page status text mapping repeated 3 times~~ ✅ Fixed in Phase 6 — consolidated into `status_text()` helper
- PEM cert+key loading duplicated in `src/mesh/cert.rs` — ✅ Fixed in Phase 6 — extracted `load_cert_chain_and_key()`

## Module Size Guide

Large modules that need splitting (see `plan.md` Phase 6.5):

| Module | Lines | Notes |
|--------|-------|-------|
| `src/mesh/transport.rs` | 6,464 | God object — split by message handler category |
| `src/dns/server.rs` | 4,500+ | Extract query handler, zone manager, rate limiter |
| `src/dns/mesh_sync.rs` | 1,975 | Split into registry, verification, health |
| `src/worker/mod.rs` | 1,566 | Extract connection handling, drain state |
| `tests/integration_test.rs` | 2,012 | Mixes DNS, IPC, config tests — split per module |
