# MaluWAF Security & Scalability Remediation Plan

**Date:** 2026-03-27
**Scope:** Address security vulnerabilities and scalability bottlenecks identified in codebase review.
**Scope Boundary:** This plan covers only security and scalability issues. Feature work, UI, DNS enhancements, and mesh networking improvements are OUT OF SCOPE.

---

## Guiding Principles

- Every change must pass `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt`
- Changes to hot paths must include benchmarks or measurements
- No new dependencies without explicit justification
- Preserve backward compatibility in config files (additive changes only)
- All new code must follow existing patterns in the codebase

---

## Phase 1: Critical Security Fixes (Week 1)

### 1.1 Increase Bcrypt Cost Factor

**File:** `src/admin/auth.rs`
**Problem:** `BCRYPT_COST = 4` is trivially brute-forceable. OWASP recommends 10-12 minimum.

**Changes:**
- Change `BCRYPT_COST` from `4` to `12`
- Add config option `admin.bcrypt_cost` (default 12, min 10, max 15) in `src/config/admin.rs`
- Log a warning if cost < 10 is configured

**Verification:**
- Existing admin auth tests in `src/admin/auth.rs` must pass
- Measure bcrypt hash time at cost 12 (should be ~250ms on modern hardware, acceptable for login)

### 1.2 Remove Plaintext Bcrypt Fallback

**File:** `src/admin/auth.rs:15-36`
**Problem:** If `bcrypt::hash()` fails, token is stored as `__plaintext__:token` and compared with `==` (timing-unsafe).

**Changes:**
- In `hash_admin_token()`: if bcrypt fails, return an error instead of a plaintext fallback
- In `verify_admin_token()`: reject any hash starting with `__plaintext__:`
- Add migration logic: detect existing `__plaintext__` hashes on startup, re-hash them with bcrypt, log a warning
- Use `subtle::ConstantTimeEq` for the comparison if any fallback path remains during migration

**Verification:**
- Test that bcrypt failure is properly propagated as an error
- Test that existing plaintext hashes are migrated on first verification
- Test that verification is constant-time for both bcrypt and migrated hashes

### 1.3 WebSocket Auth Verification (Lower Priority)

**File:** `src/admin/ws/mod.rs`, `src/admin/mod.rs:236`
**Finding:** The auth middleware layer at `src/admin/mod.rs:236` protects all routes including WebSocket endpoints. The middleware runs on the HTTP upgrade request before the handler is reached.

**Status:** Already protected. However, the WS handlers have no defense-in-depth — if the middleware layer is accidentally removed from the router, WS endpoints become unauthenticated.

**Optional hardening:**
- Add a token check inside `ws_metrics_handler` and `ws_logs_handler` as defense-in-depth
- Extract token from query parameter `?token=<value>` or `Authorization` header in the WS upgrade request
- This is LOW priority since the middleware already handles it

**Verification:**
- Test that unauthenticated WS upgrade is rejected (should already pass)
- Test that valid token allows WS upgrade (should already pass)

---

## Phase 2: Critical Scalability Fixes (Week 1-2)

### 2.1 Replace O(n) LRU with O(1) Implementation

**File:** `src/proxy_cache/store.rs:241-281`
**Problem:** `VecDeque::position()` + `VecDeque::remove()` are both O(n), called on every cache hit while holding write lock.

**Changes:**
- `linked-hash-map = "0.5"` is already in `Cargo.toml:203` — use it directly
- Replace `VecDeque<CacheKey> access_order` with `LinkedHashMap<CacheKey, ()>`
- Update all call sites:
  - `move_to_back()` → `access_order.to_back(&key)` (O(1))
  - `insert()` → `access_order.insert(key, ())` (O(1))
  - `pop_front()` → `access_order.pop_front()` (O(1))
  - `contains()` → `access_order.contains_key(&key)` (O(1))
  - `len()` → `access_order.len()` (O(1))

**Scope of changes:**
- `src/proxy_cache/store.rs` — LRU operations only
- `src/proxy_cache/key.rs` — `CacheKey` already derives `Hash, PartialEq, Eq` (verified at line 4)

**Verification:**
- Existing cache tests in `src/proxy_cache/` must pass
- Add benchmark: `get()` latency with 10K entries (before/after)
- Verify `invalidate_by_pattern()` and `invalidate_by_host()` still work correctly

### 2.2 Remove Blocking I/O from Cache Get Path

**File:** `src/proxy_cache/store.rs:228-244`
**Problem:** `std::fs::read()` called inside `get()` while holding `RwLock` write guard.

**Changes:**
- Restructure `get()` to not hold write lock during disk read:
  1. Acquire read lock, check if entry is in-memory → return immediately
  2. If entry is on disk, release read lock
  3. Perform `std::fs::read()` (or `tokio::fs::read()` if `get()` becomes async)
  4. Re-acquire read lock, update LRU, return content
- Similarly restructure `invalidate()`, `invalidate_by_pattern()`, `invalidate_by_host()`, `cleanup_expired()` to collect file paths first, release lock, then delete files

**Alternative approach:** Move disk-backed entries to a separate `DiskCache` struct with its own async runtime for I/O, keeping the in-memory cache lock-free for hot data.

**Verification:**
- Existing cache tests must pass
- Add concurrent read benchmark (multiple threads reading from cache simultaneously)
- Verify no deadlocks (run with `cargo test` under `loom` if feasible)

### 2.3 Reduce Rate Limiter Memory Footprint

**Files:** `src/waf/ratelimit.rs`, `src/config/limits.rs:16`
**Problem:** Default `max_ip_entries = 1,000,000` × ~33KB per entry = 33GB theoretical max.

**Changes:**
- Reduce default `max_ip_entries` from `1_000_000` to `100_000`
- Reduce per-IP memory by consolidating 6 `RingBuffer<Instant>` into a single time-bucketed ring buffer that tracks all 6 windows from shared timestamp data
- Target: <4KB per IP entry
- Add memory estimate to config validation: warn if `max_ip_entries * estimated_entry_size > available_memory * 0.5`

**Verification:**
- Existing rate limiter tests must pass
- Add test: create 100K entries, measure memory usage, verify < 512MB
- Verify all 6 time windows still enforce correctly

---

## Phase 3: High-Priority Security (Week 2-3)

### 3.1 TLS `skip_verify` Hardening

**File:** `src/http_client/mod.rs:201-212`
**Problem:** `NoVerifier` accepts any certificate. Enables MITM against upstream.

**Changes:**
- Add a startup warning log when any site has `skip_verify: true`
- Add `skip_verify_reason` required field when `skip_verify` is true (forces operator to document why)
- Log every request made over a skip-verify connection at WARN level (not just once)
- Consider adding a pinning mode: `skip_verify` only accepts the exact certificate seen on first connection

**File:** `src/config/site.rs` — add `skip_verify_reason: Option<String>` field

**Verification:**
- Test that `skip_verify: true` without reason produces a config validation error
- Test that requests over skip-verify connections produce WARN logs

### 3.2 IPC Key Fallback Hardening

**File:** `src/process/manager.rs:446-458`
**Problem:** If temp-file creation fails, key falls back to env var (visible in `/proc`).

**Changes:**
- Make temp-file fallback fail-hard: if temp file cannot be created, refuse to start (return error)
- Add `--allow-insecure-ipc-key` CLI flag for environments where temp files genuinely can't be created
- Document the security implications in `--help` output

**Verification:**
- Test that temp-file failure without flag causes startup error
- Test that flag allows env-var fallback
- Test that key temp file is deleted after worker reads it

### 3.3 Credential Environment Variable Override for Loki/Elasticsearch

**File:** `src/config/logging.rs:179-217`
**Problem:** `api_key` and `password` for Loki/ES accept plaintext in TOML with no env-var override.

**Changes:**
- Add env-var resolution for Loki:
  - `MALU_LOKI_PASSWORD` overrides `loki.password`
  - `MALU_LOKI_API_KEY` overrides `loki.api_key` (if applicable)
- Add env-var resolution for Elasticsearch:
  - `MALU_ES_PASSWORD` overrides `elasticsearch.password`
  - `MALU_ES_API_KEY` overrides `elasticsearch.api_key`
- Follow the same pattern as `src/config/admin.rs:60-72` (env var → config file → error)

**Verification:**
- Test that env vars override config file values
- Test that plaintext config values still work when no env var is set
- Test that sensitive values are not logged in config dump

### 3.4 Enable Global Security Headers by Default

**File:** `src/config/security.rs:14`
**Problem:** `global_security_headers` defaults to `false`.

**Changes:**
- Change default to `true`
- Ensure error pages, health endpoints, and proxy responses all include security headers when enabled
- Add migration note: users who explicitly set `global_security_headers = false` will keep their setting

**Verification:**
- Test that error responses include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`
- Test that health endpoint responses include security headers
- Test that explicit `false` in config still works

---

## Phase 4: High-Priority Scalability (Week 3-4)

### 4.1 Upstream Connection Pooling (Already Implemented)

**File:** `src/http_client/mod.rs:131-135, 168-172`, `src/proxy.rs:162-163`
**Finding:** Connection pooling IS already implemented via `hyper_util::client::legacy::Client` with built-in connection pool. Both `create_http_client_with_config()` and `create_upstream_client()` configure:
- `pool_max_idle_per_host(100)` — up to 100 idle connections per upstream
- `pool_idle_timeout(30s)` — connections idle for 30s are closed
- `enable_http2()` — HTTP/2 multiplexing is enabled
- Clients are stored in `ProxyServer` struct and reused across requests

**Status:** No work needed. Removed from remediation plan.

**Optional improvement:** Make `pool_max_idle_per_host` and `pool_idle_timeout` configurable per-site in `src/config/site.rs` (currently hardcoded to 100/30s in `src/proxy.rs:199-200`). This is LOW priority.

### 4.2 Migrate Blocking I/O in Hot Async Paths

**Files to prioritize (highest impact first):**
1. `src/proxy_cache/store.rs` — addressed in 2.2
2. `src/worker/response_builder.rs:36,39,198,270-271` — `std::fs::read()` in async context
3. `src/waf/violation_tracker.rs:95,250` — persistence reads/writes
4. `src/waf/probe_tracker.rs:128` — persistence read
5. `src/dns/resolver.rs:727` — config file read

**Changes:**
- For `response_builder.rs`: wrap `std::fs::read()` in `tokio::task::spawn_blocking()`
- For persistence files: use `tokio::fs::read()` and `tokio::fs::write()`
- For DNS resolver: use `tokio::fs::read_to_string()`
- Do NOT touch startup-only or test-only blocking I/O (acceptable as-is)

**Verification:**
- Existing tests for each module must pass
- Run with `tokio-console` to verify no blocking tasks in async runtime

### 4.3 Standardize Atomic Counter Decrement Pattern

**Files:** 43 locations across the codebase (see Phase 5 for full list)
**Problem:** Raw `fetch_sub(1, ...)` wraps to `usize::MAX` on underflow.

**Changes:**
- Replace all `fetch_sub(1, Ordering::Relaxed)` with:
  ```rust
  let _ = self.counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
  ```
- Add a helper method to shared counter types if one exists
- Priority locations: `src/waf/flood/connection_limiter.rs`, `src/metrics/mod.rs`, `src/block_store.rs`, `src/dns/limits.rs`

**Verification:**
- All existing tests must pass
- Add underflow test: decrement a zero counter, verify no panic and counter stays at 0

---

## Phase 5: Medium-Priority Security & Scalability (Week 4-6)

### 5.1 WAF Whitelist O(1) Lookup

**File:** `src/waf/mod.rs`
**Problem:** `Vec<IpAddr>::contains()` is O(n) per request.

**Changes:**
- Change whitelist storage from `Vec<IpAddr>` to `HashSet<IpAddr>` (or `AHashSet` from `ahash`)
- Update config loading to populate `HashSet` instead of `Vec`
- Update any whitelist management code (add/remove IP) to use `HashSet` operations

**Verification:**
- Existing WAF tests must pass
- Benchmark: 10K requests with 1K whitelist entries (before/after latency)

### 5.2 DHT Record Store Lock Consolidation

**File:** `src/mesh/dht/record_store.rs:75-98`
**Problem:** 20+ individual `RwLock` fields; multi-field operations require multiple locks.

**Changes:**
- Group related fields into inner structs:
  - `RecordStoreState { records, ... }`
  - `RoutingState { buckets, ... }`
  - `MetricsState { ... }`
- Lock each inner struct with a single `RwLock`
- Update all access patterns to lock the appropriate group

**Verification:**
- Existing DHT/mesh tests must pass
- Run with `cargo test --features mesh` to verify mesh integration

### 5.3 Static Worker Thread Pool

**File:** `src/worker/mod.rs:464-484`
**Problem:** `std::thread::spawn()` per connection creates unbounded OS threads.

**Changes:**
- Replace with a bounded thread pool (e.g., `rayon::ThreadPool` or custom `ThreadPool` with `crossbeam-channel`)
- Default pool size: `num_cpus * 2` (configurable)
- Queue connections when pool is full instead of spawning new threads

**Verification:**
- Existing worker tests must pass
- Add test: send 1000 connections, verify thread count stays bounded

### 5.4 Connection Limiter Lock-Free Queue

**File:** `src/waf/traffic_shaper/limiter.rs:104-109`
**Problem:** Write lock on `connection_queue` (`Vec` under `RwLock`) for every queued connection.

**Changes:**
- Replace `RwLock<Vec<oneshot::Sender>>` with `tokio::sync::mpsc::bounded_channel`
- Use `channel.try_send()` for non-blocking queue check
- Remove the `RwLock` entirely

**Verification:**
- Existing traffic shaper tests must pass
- Add concurrent connection pressure test

### 5.5 Input Normalization Buffer Reuse

**File:** `src/waf/attack_detection/normalizer.rs:20`
**Problem:** Up to 10 decode passes per request, each allocating `Vec<char>`.

**Changes:**
- Use `thread_local!` buffer pool for decode passes
- Reuse `String` and `Vec<char>` buffers across requests on the same thread
- Consider operating on `&[u8]` slices instead of `Vec<char>` where possible

**Verification:**
- Existing attack detection tests must pass (especially double-encoding tests)
- Benchmark: normalization latency before/after

### 5.6 Deprecate `X-XSS-Protection: 1; mode=block`

**File:** `src/config/site.rs:1506-1508`
**Problem:** Modern browsers removed XSS auditor; `1; mode=block` can introduce vulnerabilities in older browsers.

**Changes:**
- Change default from `"1; mode=block"` to `"0"`
- Add comment explaining why `"0"` is preferred

**Verification:**
- Test that default config produces `X-XSS-Protection: 0`

---

## Phase 6: Low-Priority Cleanup (Week 6-8)

### 6.1 Audit `unwrap()`/`expect()` on Request Paths

**Priority locations:**
- `src/proxy.rs:397,412,485,954`
- `src/tls/server.rs:697,710,726`
- `src/worker/mod.rs:257`
- `src/mesh/proxy.rs:604,996`
- `src/server/mod.rs:182,188`

**Changes:**
- Replace `.expect()` with `?` operator or proper error handling
- Replace `.unwrap()` with `match` or `.ok_or()?` where possible
- For truly infallible operations (e.g., `"close".parse()`), add `#[allow(clippy::unwrap_used)]` with a comment explaining why it's safe

**Verification:**
- `cargo clippy -- -D warnings` must pass
- All existing tests must pass

### 6.2 Sanitize Logged Paths

**File:** `src/proxy.rs:541,548,559`
**Problem:** Full URL paths logged at INFO may contain tokens/PII in query strings.

**Changes:**
- Strip query parameters from logged paths
- Or log only the path component, not the full URI
- Add `log_query_params` config option (default `false`) for operators who need it

**Verification:**
- Test that query parameters are stripped from logs by default
- Test that `log_query_params = true` restores full logging

### 6.3 Remove Token from Validation Error

**File:** `src/config/admin.rs:105-109`
**Problem:** Generated token returned in validation error message (could appear in logs).

**Changes:**
- Remove the generated token from the error message
- Log the generated token separately at INFO level (once, on startup)
- Error message should say: "Admin token must be at least X characters. Set MALU_ADMIN_TOKEN env var or configure admin.token."

**Verification:**
- Test that error message does not contain a token
- Test that startup log contains the generated token

---

## Verification Checklist (Per Phase)

After each phase, run:

```bash
# Format check
cargo fmt --check

# Lint (must pass with zero warnings)
cargo clippy -- -D warnings

# Full test suite
cargo test

# Integration tests (fast)
cargo test --test integration_test

# Check with all default features
cargo check

# Check with DNS feature
cargo test --features dns

# Check with mesh feature
cargo test --features mesh
```

## Out of Scope

The following are explicitly excluded from this plan:
- Feature development (new WAF rules, new attack detection, new protocols)
- UI/UX changes
- DNS server enhancements
- Mesh networking improvements
- Plugin system changes
- Build system changes
- Documentation updates (except inline code comments required by changes)
