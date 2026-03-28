# MaluWAF Codebase Improvement Plan

## Summary

Based on a comprehensive code review of ~183K lines across 66 modules. The project compiles cleanly and passes integration tests, but has accumulated technical debt in error handling, dead code, async safety, and code organization. This plan prioritizes fixes by severity.

---

## Phase 1: Critical Correctness & Safety

### 1.1 Fix IPC Lock Contention

**Severity: Critical** — Real deadlock/starvation risk in production.

`clippy::await_holding_lock` is suppressed globally in `src/lib.rs:5`, hiding a genuine hazard. Three worker tasks compete for `Arc<TokioMutex<IpcStream>>`:

- Heartbeat task: `src/worker/mod.rs:173-193`
- IPC listener task: `src/worker/mod.rs:196-249` — holds lock during `recv_with_timeout`, then re-acquires it to send a response
- HTTP server task: `src/worker/mod.rs:254-325`

**Tasks:**
1. Audit all `.lock().await` call sites in `src/worker/mod.rs` and submodules
2. Determine if IPC stream can be replaced with a channel-based design (e.g., `tokio::sync::mpsc` for outgoing messages, dedicated writer task)
3. If channel redesign is too invasive, add per-site `#[allow(clippy::await_holding_lock)]` with explicit justification comments
4. Remove the crate-wide suppression from `src/lib.rs:5`
5. Add a test or lint check to prevent re-introduction of the global suppression

**Files:** `src/lib.rs`, `src/worker/mod.rs`, `src/worker/connect.rs`, `src/worker/unified_server.rs`

### 1.2 Replace `duration_since(UNIX_EPOCH).unwrap()` with `safe_unix_timestamp()`

**Severity: High** — 111 occurrences across 50 files; 48 of those call `.unwrap()` on the next line.

A safe helper already exists at `src/mesh/mod.rs:50-55`:
```rust
pub fn safe_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
```

**Affected files (by occurrence count):**
- `src/dns/trust_anchor.rs` — 11
- `src/waf/threat_level/persistence/sqlite.rs` — 7
- `src/dns/dnssec.rs` — 6
- `src/process/pidfile.rs` — 5
- `src/mesh/transport.rs` — 4
- `src/mesh/transport_global.rs` — 4
- `src/dns/anycast_sync.rs` — 4
- `src/waf/threat_level/baseline.rs` — 4
- `src/mesh/transport_peer.rs` — 3
- `src/mesh/transport_org.rs` — 3
- `src/dns/prefetch.rs` — 3
- `src/block_store.rs` — 3
- `src/udp/listener.rs` — 3
- `src/waf/violation_tracker.rs` — 3
- `src/mesh/transport_connection.rs` — 2
- `src/mesh/rate_limit.rs` — 2
- `src/http/server.rs` — 2
- `src/honeypot_port/storage.rs` — 2
- `src/dns/tsig.rs` — 2
- `src/dns/server/mod.rs` — 2
- `src/admin/handlers/sites.rs` — 2
- `src/static_files/mod.rs` — 2
- `src/static_files/directory.rs` — 2
- `src/utils.rs` — 2
- `src/overseer/process.rs` — 2
- 25 more files with 1 occurrence each (including `src/waf/rule_feed.rs`, `src/dns/anycast.rs`, `src/captcha/mod.rs`, `src/process/manager.rs`, `src/process/ipc.rs`, etc.)

**Tasks:**
1. Grep for all `duration_since.*UNIX_EPOCH.*unwrap` patterns
2. Replace each with `crate::mesh::safe_unix_timestamp()` or a locally-scoped equivalent if the mesh module isn't in scope
3. If `safe_unix_timestamp()` is only in `mesh`, extract it to `src/utils.rs` as a crate-wide utility
4. Verify no call site needs the `Duration` (not just seconds) — if so, create a `safe_unix_duration()` variant

### 1.3 Replace `std::process::exit()` with Graceful Shutdown

**Severity: High** — Bypasses Drop impls, leaks resources.

Three `std::process::exit` calls in worker code:
- `src/worker/mod.rs:323` — `exit(100)` for threadpool resize
- `src/worker/unified_server.rs:811` — `exit(100)` for threadpool resize
- `src/worker/unified_server.rs:838` — `exit(1)` when master dies

**Tasks:**
1. Replace `exit(100)` calls with a shutdown signal (return a `Result` or send a signal via watch channel)
2. Replace `exit(1)` with a proper error propagation path
3. Ensure the master process handles worker exit codes correctly (exit 100 = resize, exit 1 = error)
4. Audit other `std::process::exit` calls in the codebase for the same pattern (e.g., `src/main.rs`, `src/bin/server.rs`)

---

## Phase 2: Error Handling Unification

### 2.1 Adopt `WafError` or Remove It

**Severity: Medium** — Two parallel error systems cause inconsistency.

Current state:
- `src/error.rs` defines `WafError` with 10 variants and `WafErrorExt` trait — well-designed but **completely unused in production code** (0 call sites outside `error.rs` itself)
- 206 call sites use `Box<dyn std::error::Error + Send + Sync>` (aliased as `BoxResult`/`BoxError`)
- Many modules return `Result<_, String>` (e.g., `src/dns/dnssec.rs`, config modules)

**Option A: Adopt `WafError` (recommended)**
1. Add missing variants to `WafError` for DNS, mesh, and proxy error categories
2. Replace `String` errors in `src/dns/dnssec.rs` with `WafError::Dnssec(...)` variant
3. Replace `Box<dyn Error>` in `src/http/server.rs`, `src/tls/cert_resolver.rs`, `src/tunnel/quic/server.rs` with `WafError`
4. Remove blanket `From<String>` and `From<&str>` impls that lose type information
5. Keep `Box<dyn Error>` only at top-level binary entry points (`main.rs`, `bin/server.rs`)

**Option B: Remove `WafError`**
1. Delete `src/error.rs` and `WafErrorExt` trait
2. Standardize on `Box<dyn std::error::Error + Send + Sync>` everywhere
3. Document the decision in `AGENTS.md`

**Decision needed before proceeding.**

---

## Phase 3: Dead Code Cleanup

### 3.1 Audit and Prune `#[allow(dead_code)]` Annotations

**Severity: Medium** — 128 annotations across 66 files obscure real unused code.

**Definitely remove (stub/speculative):**
- `src/plugin/wasm_runtime.rs:30-36` — `WasmRuntime` has 3 of 4 fields dead; remove the struct or implement the feature
- `src/mesh/transports/wireguard.rs:26-51` — 8 fields for unimplemented WireGuard features; keep only if WireGuard is actively being developed
- `src/waf/ratelimit.rs:49,96` — `IpRateLimitState::new()` and `RingBuffer::with_capacity()` private constructors never called outside tests; gate under `#[cfg(test)]`
- `src/worker/mod.rs:43-96` — `MinifierCache`, `get_content_type`, `get_compressed_content`, `ListenerType`; remove or conditionally compile

**Keep (genuinely planned):**
- `src/overseer/upgrade.rs:803-816` — drain state tracking fields (used during upgrades)
- `src/dns/cookie.rs:23` — DNS cookie validation
- `src/dns/hsm.rs:66` — HSM key identification

**Tasks:**
1. For each `#[allow(dead_code)]`, determine if the item is reachable from any code path
2. Remove dead items entirely; for conditionally-dead items, use `#[cfg(feature = "...")]` instead
3. After removal, run `cargo check` with all feature combinations to verify no breakage
4. Remove the global `dead_code` suppressions from `src/lib.rs` if any remain

### 3.2 Remove Duplicate Static 500 Response Pattern

**Severity: Low** — 8+ occurrences of identical response construction.

Current locations:
- `src/proxy.rs:397,412,485,954`
- `src/tls/server.rs:697,710,726`

**Tasks:**
1. Extract to a shared function in `src/http/mod.rs` or `src/utils.rs`:
   ```rust
   pub fn internal_server_error() -> Response<Full<Bytes>> { ... }
   ```
2. Replace all call sites
3. Verify no site customizes the 500 body differently

---

## Phase 4: Code Organization

### 4.1 Split Large Functions

**Severity: Medium** — 20+ functions exceed 200 lines.

**Priority targets (function > 500 lines):**

| File | Function | Lines | Strategy |
|------|----------|-------|----------|
| `src/mesh/protocol_proto_encode.rs:4` | `from` (trait impl) | ~1985 | Already protobuf-generated pattern; extract per-variant helpers |
| `src/mesh/protocol_proto_decode.rs:18` | `try_from` | ~1204 | Same as above |
| `src/admin/handlers/config.rs:70` | `get_config_schema` | ~879 | Extract schema sections into named functions |
| `src/worker/unified_server.rs:108` | `run_unified_server_worker` | ~736 | Extract listener setup, connection loop, shutdown handling |
| `src/http/server.rs:302` | `handle_request` | ~678 | Extract route dispatch, error handling, response building |
| `src/waf/attack_detection/patterns.rs:466` | `jwt` | ~622 | Extract pattern categories into sub-functions |

**Tasks:**
1. Start with `get_config_schema` — extract each config section (TLS, DNS, WAF, mesh) into its own function
2. Split `run_unified_server_worker` into `setup_listeners`, `accept_loop`, `handle_shutdown`
3. Split `handle_request` into routing, middleware, and response construction phases
4. Proto encode/decode — these follow a generated pattern and are lower priority; can remain large if they're auto-generated

### 4.2 Extract IPC `Message` Enum

**Severity: Low** — 40+ variants mixing 5+ concerns.

Current state: `src/process/ipc.rs:172` contains lifecycle, threat intel, caching, commands, and DNS variants in a single enum.

**Tasks:**
1. Group variants by concern with inner enums:
   ```rust
   pub enum Message {
       Lifecycle(LifecycleMessage),
       ThreatIntel(ThreatIntelMessage),
       Cache(CacheMessage),
       Command(CommandMessage),
       Dns(DnsMessage),
   }
   ```
2. Update all match sites to use nested matching
3. This is a large refactor — defer until other phases are complete

### 4.3 Consolidate Timestamp Utility

**Severity: Low** — `safe_unix_timestamp()` lives in `src/mesh/mod.rs` but is needed crate-wide.

**Tasks:**
1. Move `safe_unix_timestamp()` from `src/mesh/mod.rs:50-55` to `src/utils.rs`
2. Add `safe_unix_duration()` variant for call sites that need `Duration` not just seconds
3. Update `src/mesh/mod.rs` to re-export or call the utility
4. Complete Phase 1.2 replacements using the consolidated location

### 4.4 Reduce Wildcard Imports in Production Code

**Severity: Low** — 202 `use ...::*` occurrences; ~10 in production mesh transport files.

Production wildcard imports:
- `src/mesh/transport_global.rs:1`
- `src/mesh/transport_dns.rs:1`
- `src/mesh/transport_org.rs:1`
- `src/mesh/transport_dht.rs:1`
- `src/mesh/transport_rate_limit.rs:1`
- `src/mesh/transport_connection.rs:1-2`
- `src/mesh/transport_peer.rs:1-2`
- `src/mesh/transport_routing.rs:1-2`
- `src/plugin/wasm_runtime.rs:7` — `use wasmtime::*;`

**Tasks:**
1. For each file, determine which items from the wildcard import are actually used
2. Replace with explicit imports
3. This is cosmetic — do last or skip if mesh transport is being actively restructured

---

## Phase 5: Testing & Documentation

### 5.1 Add End-to-End Process Lifecycle Test

**Severity: Medium** — No test verifies overseer → master → worker lifecycle.

**Tasks:**
1. Create `tests/e2e_process_test.rs`
2. Test: spawn overseer, verify master starts, verify worker starts, send SIGTERM, verify graceful shutdown
3. Use temporary Unix sockets and config files
4. Gate behind a feature flag or long-test marker to avoid slowing CI

### 5.2 Fix IPC Test Duplication

**Severity: Low** — `tests/ipc_test.rs` manually reimplements wire protocol framing instead of using `IpcStream`.

**Tasks:**
1. Refactor IPC tests to use the actual `IpcStream` abstraction from `src/process/ipc.rs`
2. Keep one raw-socket test as a regression test for wire compatibility
3. Verify tests pass after Phase 1.1 IPC changes

### 5.3 Add Public API Documentation

**Severity: Low** — Core types lack doc comments.

**Priority items:**
- `src/error.rs:8` — `pub enum WafError`
- `src/buffer/pool.rs` — `BufferPool`, `BufferPoolConfig`, `PoolStats`
- `src/process/ipc.rs` — `Message` enum and `WorkerId` (partially documented)
- `src/lib.rs` — add crate-level documentation (`//!`)

---

## Execution Order

| Phase | Depends On | Estimated Scope | Risk |
|-------|-----------|----------------|------|
| 1.2 (safe_unix_timestamp) | None | ~50 files, mechanical | Low |
| 3.1 (dead code audit) | None | ~50 files, mechanical | Low |
| 1.3 (process::exit) | None | 2-3 files | Low |
| 3.2 (duplicate 500 response) | None | ~2 files | Low |
| 2.1 (error unification) | None | ~30+ files, high churn | Medium |
| 1.1 (IPC lock contention) | None | ~4 files, design change | High |
| 4.3 (consolidate timestamp) | 1.2 | 2-3 files | Low |
| 4.1 (split large functions) | None | ~6 files | Medium |
| 5.2 (IPC test refactor) | 1.1 | 1 file | Low |
| 4.2 (IPC message grouping) | 1.1, 4.1 | ~10+ files | High |
| 4.4 (wildcard imports) | None | ~10 files | Low |
| 5.1 (e2e process test) | 1.1 | 1 new file | Low |
| 5.3 (doc comments) | None | ~4 files | Low |

## Verification

After each phase:
```bash
cargo check                    # Must compile
cargo test --test integration_test  # Must pass (40 tests)
cargo clippy -- -D warnings    # No new warnings introduced
cargo fmt --check              # Formatting consistent
```

After all phases:
```bash
cargo test                     # Full test suite
cargo test --features dns      # With DNS feature
cargo test --no-default-features  # Minimal feature set
```
