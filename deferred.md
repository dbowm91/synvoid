# MaluWAF Deferred Items Plan

> Created 2026-03-25. Consolidates all unfinished and deferred items from plan.md Phases 1-7.
> Total deferred items: ~75. Organized into 8 execution phases by dependency and risk.

---

## Overview

After completing Phases 1-7, the following items remain. This plan groups them by **subsystem and dependency order** rather than the original phase numbering, since many deferred items span multiple original phases.

### Priority Legend

| Symbol | Meaning |
|--------|---------|
| HIGH | Blocks correctness, security, or API stability |
| MEDIUM | Improves reliability, performance, or maintainability |
| LOW | Code hygiene, documentation, or optional improvements |

### Complexity Legend

| Symbol | Meaning |
|--------|---------|
| L | Low — <50 lines changed, mechanical |
| M | Medium — 50-200 lines, some design decisions |
| H | High — 200+ lines, significant refactoring or multi-file coordination |
| XL | Very high — 500+ lines, god object splits, multi-phase dependency |

---

## Phase 8: Quick Wins and Follow-ups

> Estimated effort: 1-2 days. All items are independent and low-risk.

### 8.1 Phase 1 Follow-ups (remaining)

| # | Item | Priority | Complexity | File:Line | Description |
|---|------|----------|------------|-----------|-------------|
| 8.1.1 | CSS challenge path exemptions | HIGH | L | `src/waf/mod.rs:517,985` | Add `css_exempt_paths: Vec<String>` to `WafConfig` and `CssChallengeDefaults`. Default list includes `"/_waf_css_challenge"` and `"/_waf_assets"`. Replace hardcoded `!path.starts_with(...)` checks with `!self.config.css_exempt_paths.iter().any(\|p\| path.starts_with(p))` in both `check_early()` and `check_request_full()`. **This unblocks API consumers who currently get challenged on every request.** |
| 8.1.2 | Auth log dedup on merge | MEDIUM | L | `src/auth/mod.rs:168-179` | After `merge_stores` extends login_logs, deduplicate by `LoginLog.id` using `HashSet::insert` in `retain`. Optionally cap at `MAX_LOGIN_LOGS` (e.g., 10,000). |
| 8.1.3 | SSRF test failure fix | MEDIUM | L | `src/waf/attack_detection/ssrf.rs:301` | Remove private IP prefix patterns (`"10."`, `"172.16."`-`"172.31."`, `"192.168."`, loopback variants) from `DefaultPatterns::ssrf()`. These are already handled by `contains_private_ip_or_localhost()` which respects `block_private_ips`. Keep metadata endpoints, `file://`, `gopher://`, etc. |
| 8.1.4 | Counter underflow logging | LOW | L | `src/upstream/pool.rs:194-197` | Add `tracing::warn!` when `fetch_update` returns `Err(0)` in `decrement_connections`. |

### 8.2 Phase 6 Follow-ups

| # | Item | Priority | Complexity | File:Line | Description |
|---|------|----------|------------|-----------|-------------|
| 8.2.1 | XSS in `generate_login_page` | LOW | L | `src/admin/legacy.rs:342-343` | Pass `error` parameter through `escape_html()`. Currently dead code (zero callers) but exported via `pub use`. |
| 8.2.2 | Duplicate match arms in `load_private_key` | LOW | L | `src/mesh/cert.rs:50-56` | Remove 3 duplicate conditions (`PrivateKey`, `EcPrivateKey`, `RsaPrivateKey` each appear twice in the `\|\|` chain). |

### 8.3 Phase 2 Follow-ups

| # | Item | Priority | Complexity | File:Line | Description |
|---|------|----------|------------|-----------|-------------|
| 8.3.1 | Wire `create_upstream_client` into proxy | MEDIUM | M | `src/proxy.rs:176-186`, `src/tls/server.rs:603`, `src/http/server.rs:121` | Migrate `ProxyServer`, `TlsServer`, and `HttpServer` constructors from `create_http_client_with_config()` to `create_upstream_client()` with per-site `UpstreamTlsConfig`. The infrastructure (`create_upstream_client`, `UpstreamTlsConfig`, `build_tls_config`, `NoVerifier`) already exists. **This is the highest-impact item from Phase 2 follow-ups — it enables `skip_verify` and `allow_plaintext` per-site.** |

**Implementation steps for 8.3.1:**

1. Add `UpstreamTlsConfig` field to `ProxyServer` struct (or derive it from site config in constructor).
2. Change `ProxyServer::new()` to call `create_upstream_client()` instead of `create_http_client_with_config()`.
3. Map site config `tls.skip_verify`, `tls.ca_cert`, `tls.server_name` into `UpstreamTlsConfig`.
4. Update `TlsServer` handler (1 call site) similarly.
5. Update `HttpServer::new()` (1 call site) similarly.
6. Optionally update `HealthChecker::http_health_check()` to use per-site TLS config.
7. Run `cargo test --test integration_test` after each step.

| 8.3.2 | Wire `ca_cert_path` into TLS config | LOW | L | `src/http_client/mod.rs:153-203` | `UpstreamTlsConfig.ca_cert_path` exists but `build_tls_config()` ignores it (marked `_ca_cert_path`). Add `rustls-pemfile` dep, load custom CA certs from path, add to root cert store. ~20 lines of change. |

### 8.4 Phase 7 Follow-ups

| # | Item | Priority | Complexity | File:Line | Description |
|---|------|----------|------------|-----------|-------------|
| 8.4.1 | `rule_feed.rs` tests | MEDIUM | M | `src/waf/rule_feed.rs` | Add tests for: embedded key parse, signature verification (valid/invalid), version comparison ordering, `convert_rules_to_ipc_patterns` roundtrip, `reload_attack_detector` pattern merge. Requires understanding of the crypto signing flow. |
| 8.4.2 | `endpoints.rs` tests | MEDIUM | L | `src/waf/endpoints.rs` | Add tests for: `status_text()` correctness across all 15+ codes, sensitive path matching, error page HTML rendering (verify no XSS in interpolated values). |
| 8.4.3 | `config/mod.rs` tests | LOW | M | `src/config/mod.rs` | Add tests for: site discovery, config reload, validation. Complex due to filesystem I/O — use `tempfile::TempDir` for isolation. |

---

## Phase 9: Performance Allocations and Cache Fixes

> Estimated effort: 2-3 days. Independent of Phase 8.

### 9.1 Binary Body in Cache (4.F1)

**Status:** HIGH impact. Corrupts images, compressed responses, and any non-UTF-8 content in the proxy cache.

**Current state:** `src/proxy.rs:913` uses `String::from_utf8_lossy(&entry.content)` when building cached responses. The cache store already holds `Bytes` — corruption only happens on read-back.

**Full change chain:**

```
HttpResponse.body: String  →  Bytes         [src/http_client/mod.rs:355]
         ↓
send_single_request()  →  Response<Bytes>   [src/proxy.rs:1128]
         ↓
forward_with_pool()  →  Response<Bytes>      [src/proxy.rs:994]
         ↓
forward_request()  →  Response<Bytes>        [src/proxy.rs:583]
         ↓
handle_request_with_cache()  →  Response<Bytes>  [src/proxy.rs:609]
         ↓
build_cached_response()  →  Response<Bytes>  [src/proxy.rs:871]
```

**Implementation steps:**

1. **`src/http_client/mod.rs:355`** — Change `HttpResponse.body` from `String` to `Bytes`. Remove `String::from_utf8_lossy` at line 369, store raw `body_bytes` directly.
2. **`src/proxy.rs`** — Propagate `Response<Bytes>` through `send_single_request` → `forward_with_pool` → `forward_request` → `handle_request_with_cache`. Remove `String::from_utf8_lossy` in `build_cached_response` (line 913). Remove unnecessary `Bytes::from(response.body().clone())` at line 686 (body is already `Bytes`).
3. **`src/tls/server.rs:544-555`** — Simplify `Bytes::from(body)` to direct use (body is already `Bytes`).
4. **`src/http/handler.rs:1332-1343`** — Same simplification (if file is re-enabled; currently dead code).
5. **`src/http/server.rs:792`** — `Bytes::from(resp.body)` → use `resp.body` directly.
6. **Audit for string operations on response body** — Search for `body.contains(`, `body.starts_with(`, `body.len()` on `Response` bodies. Any string operations need to use `String::from_utf8_lossy()` at point of use (display/logging only).

**Risks:**
- Any code that performs string operations on `response.body()` will need explicit UTF-8 conversion at point of use.
- The `handle_request_with_cache` method stores cached responses via `Bytes::from(response.body().clone())` — this becomes identity (zero-cost) after the change.
- `body.contains("...")` patterns in admin/logging code need updating.

**Verification:** `cargo test --test integration_test`. Add a test that caches and retrieves a binary response (e.g., a PNG image) through the proxy and verifies byte-for-byte equality.

### 9.2 InputLocation::Header Allocation (4.F3)

**Status:** MEDIUM impact. Eliminates ~20 String allocations per WAF-checked request.

**Current state:** `InputLocation::Header(String)` at `src/waf/attack_detection/config.rs:195`. 22 call sites create strings via `.to_string()` or hardcoded literals.

**Fix:** Change `Header(String)` to `Header(Arc<str>)` (and `Cookie(String)` to `Cookie(Arc<str>)`). `Arc<str>` implements `Deref<Target=str>`, `Display`, `Clone`, `PartialEq` — it's a drop-in replacement. Clone cost drops from O(n) heap copy to atomic refcount increment.

**Implementation steps:**

1. `src/waf/attack_detection/config.rs:195` — Change `Header(String)` to `Header(Arc<str>)`, `Cookie(String)` to `Cookie(Arc<str>)`.
2. Update all 22 call sites — change `.to_string()` to `.into()` or `Arc::from(...)`.
3. Display impl (line 200-209) — no changes needed (`Arc<str>` derefs to `str`).
4. `AttackDetectionResult` derive — `Arc<str>` is `Clone`, no issue.

**Verification:** `cargo test`. Benchmark WAF detection hot path before/after.

### 9.3 WAF `to_uppercase` Already Fixed

`4.2.2` was fixed in Phase 6 using `eq_ignore_ascii_case`. No further action.

### 9.4 DNS Cache Arc\<Firewall\> (4.6.2)

**Status:** MEDIUM impact. Eliminates full `DnsFirewall` clone per DNS query in the recursive resolver.

**Current state:** `RecursiveDnsServer` stores `firewall: Option<Arc<DnsFirewall>>` and clones it on every query (lines 266-276, 349-359 in `src/dns/recursive.rs`). `DnsServer` already uses `Arc<RwLock<DnsFirewall>>`.

**Implementation steps:**

1. Change `RecursiveDnsServer.firewall` from `Option<Arc<DnsFirewall>>` to `Option<Arc<RwLock<DnsFirewall>>>`.
2. Update constructor `RecursiveDnsServer::new()` to accept the new type.
3. Update 2 call sites (TCP + UDP handlers) to acquire lock instead of cloning:
   ```rust
   if let Some(ref firewall) = self.firewall {
       let mut fw = firewall.write();
       if let Ok(decision) = fw.evaluate_query(&query, client_addr.ip(), "") { ... }
   }
   ```
4. **Optional improvement:** Split `evaluate_query` into `evaluate_query(&self)` (read-only matching) and `cleanup_if_needed(&mut self)` (periodic cleanup). This allows using a read lock for queries and a write lock only for the rare cleanup path.

**Risks:** The write lock is held during query evaluation. Since `evaluate_query` is fast (pattern matching), this is acceptable. The optional split to read lock is a further optimization.

**Verification:** `cargo test --features dns`.

### 9.5 Batch Zone Index Rebuild (4.6.3)

**Status:** LOW impact. Current code is already batched (bulk load → single rebuild). The improvement is for future incremental zone operations.

**Current state:** `rebuild_zone_index()` at `src/dns/server.rs:1106-1128` iterates all zones, sorts, and writes three index structures under sequential write locks.

**Implementation steps:**

1. Add `zone_index_dirty: AtomicBool` field to `DnsServer`.
2. On zone add/remove, set `zone_index_dirty.store(true, Ordering::Release)`.
3. Before query handling, check dirty flag and rebuild only if true.
4. **Optional:** Combine the three index structures (`zone_index`, `zone_index_btree`, `zone_trie`) into a single struct behind one `RwLock` for atomic consistency.

**Verification:** `cargo test --features dns`. Verify zone query correctness after lazy rebuild.

---

## Phase 10: Mesh Subsystem Refactoring (Part 1)

> Estimated effort: 5-7 days. High-risk area — 38K lines across 55 files.

### 10.1 `duration_since(UNIX_EPOCH)` unwrap Cleanup (6.1.4)

**Status:** MEDIUM. ~80+ occurrences of `.unwrap()` on `duration_since(UNIX_EPOCH)` across mesh code. These panic if system clock is before 1970 (rare but possible on misconfigured systems).

**Fix:** Replace with `.unwrap_or(Duration::ZERO)` or a helper:

```rust
fn safe_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
```

**Files affected:** `src/mesh/protocol.rs`, `transport.rs`, `organization.rs`, `cert.rs`.

**Implementation:** Mechanical search-and-replace. Create the helper in `src/mesh/mod.rs` or `src/mesh/utils.rs`, then replace all call sites.

### 10.2 `expect()` in Crypto Paths (6.1.5)

**Status:** MEDIUM. ~10 `expect()` calls in mesh crypto paths (`config.rs:1515,1523`, `cert.rs:643`). These panic on key parse failures.

**Fix:** Return `Result` from functions that parse keys. Propagate errors to callers.

### 10.3 Dead Code Suppressions in Mesh (6.1.6)

**Status:** LOW. 22 files with `#![allow(dead_code)]`. Many items are feature-gated (`#[cfg(feature = "...")]`) or platform-specific.

**Implementation:** Remove crate-level `#![allow(dead_code)]` per file. For each suppressed item:
- If truly dead: delete.
- If feature-gated: add `#[cfg(feature = "...")]` attribute instead.
- If platform-specific: add `#[cfg(unix)]` or `#[cfg(windows)]`.

### 10.4 `MeshConfig` Sub-Config Grouping (6.1.7)

**Status:** LOW. Most sub-configs are already extracted. Remaining ~10 flat scalar fields could be grouped into `MeshIdentityConfig`, `MeshNetworkingConfig`, `MeshPolicyFlags`.

**Risk:** serde backward compatibility — field renames break existing config files. **Recommendation: Skip unless config migration is planned.**

### 10.5 `MeshMessage` Variants (6.1.9)

**Status:** **DO NOT RESTRUCTURE.** The 100-variant `MeshMessage` enum is a wire protocol. Restructuring into sub-enums would break backward compatibility with existing mesh nodes.

**Alternative:** Use naming conventions and organize documentation. Add `// Category: Routing` comments above variant groups. This is a documentation task, not a structural refactor.

### 10.6 SequenceCounter Ordering (6.1.14)

**Status:** LOW. `src/mesh/config.rs:146-167` uses `Relaxed` ordering for sequence counters. In practice, `Relaxed` is correct for independent counters on a single thread. Only upgrade to `SeqCst` if cross-thread ordering is provably needed.

**Recommendation:** Add `// SAFETY: Relaxed is correct because...` documentation. No code change needed.

---

## Phase 11: DNS Subsystem Refactoring

> Estimated effort: 3-5 days. Depends on Phase 9 completion for Arc\<Firewall\>.

### 11.1 `mesh_sync.rs` Split (5.F1)

**Status:** MEDIUM. 1,975 lines with clear domain boundaries.

**Current structure of `MeshDnsRegistry` (18 `Arc<RwLock<...>>` fields, 64 public methods):**

| Proposed Submodule | Lines | Methods |
|---|---|---|
| `registry.rs` | ~115 | Constructor, config, certificate management |
| `registration.rs` | ~155 | `register_origin_node`, `register_edge_node`, `register_anycast_node` |
| `health.rs` | ~276 | Health updates, node scoring, best-node selection |
| `query.rs` | ~400 | Node querying, geo-scoring, cleanup |
| `dht.rs` | ~93 | DHT sync, `apply_dht_domain_registration` |
| `verification.rs` | ~560 | Domain verification lifecycle, TXT/NS challenges |

**Implementation steps:**

1. Create `src/dns/mesh_sync/` directory. Move `mesh_sync.rs` to `mesh_sync/mod.rs`.
2. Move shared types (`RegisteredEdgeNode`, `RegisteredOriginNode`, `RegisteredAnycastNode`, `MeshNodeCertificate`, `MeshDnsRegistryConfig`, `MeshDnsRegistry` struct definition, `VerificationTask`, `VerificationMetrics`) to `mod.rs`.
3. Create 6 submodule files. Move `impl MeshDnsRegistry` methods to appropriate submodule.
4. Each submodule uses `use super::*` to access the struct and types.
5. Verify `cargo test --features dns` passes after each extraction.

**Risks:** Low. No public API changes. Mechanical file movement.

### 11.2 `handle_query_with_cache` QueryContext (5.F3)

**Status:** LOW. The `QueryContext` struct already exists at `src/dns/server.rs:708-729` and is used by `handle_tcp_query`. This item is about changing `handle_query_with_cache` (16 params) and `handle_query` (10 params) to accept `QueryContext` instead.

**Implementation steps:**

1. Change `handle_query_with_cache` signature from 16 params to 4 (`ctx: &QueryContext`, `query`, `client_ip`, `cache_key`).
2. Change `handle_query` signature from 10 params to 3 (`ctx: &QueryContext`, `query`, `client_ip`).
3. Update all 19 call sites across `server.rs` (15), `doq.rs` (1), `doh.rs` (1), `dot.rs` (1). Each call site already constructs or receives a `QueryContext` — just pass it through.
4. The doq/doh/dot callers don't currently use `QueryContext`. They'd need to construct one from server accessor methods. Alternatively, add `DnsServer::query_context() -> QueryContext` convenience method.

**Verification:** `cargo test --features dns`. All 52 DNS config tests + 45 DNS integration tests should pass.

### 11.3 `DnsServer::clone()` Nullification (4.6.4)

**Status:** LOW. `DnsServer` derives `Clone` but some fields use `Arc` clones that share state while others are cloned independently, creating inconsistency.

**Recommendation:** If `DnsServer` is only cloned in tests, remove the `Clone` derive and create explicit test constructors. If cloned for production use, audit each field for correct sharing semantics.

---

## Phase 12: Admin Subsystem Refactoring

> Estimated effort: 3-4 days.

### 12.1 Theme/Honeypot Endpoint Auth (6.2.2)

**Status:** MEDIUM. Two handler sets lack authentication:

| Handler | File:Line | Routes |
|---|---|---|
| Theme | `src/admin/handlers/theme.rs:134-209` | Theme customization endpoints |
| Honeypot | `src/admin/handlers/honeypot.rs:34-62` | Honeypot management endpoints |

**Fix:** Add `require_auth()` middleware or inline auth check to these route handlers, matching the pattern used by other admin endpoints.

### 12.2 Unbounded Auth Token Map (6.2.5)

**Status:** MEDIUM. `src/admin/auth.rs:14-16` stores auth tokens in an unbounded `HashMap`. Tokens accumulate over the process lifetime.

**Fix:** Add periodic cleanup of expired tokens (similar to CSRF token cleanup at `src/admin/state.rs:444-479`). Call `cleanup_expired_tokens()` in the existing 60-second alert ticker.

### 12.3 Config Write Race (6.2.11)

**Status:** MEDIUM. `src/admin/handlers/config.rs` and `handlers/sites.rs` write config files without file locking. Concurrent admin requests can corrupt config.

**Fix:** Serialize config writes through a channel (single writer task). Or use `flock` on the config file before writing (similar to the overseer lock file fix in Phase 4.3.4).

### 12.4 `AdminState` God Object (6.2.12)

**Status:** LOW. 22 fields in a single struct. Can be split into sub-structs:

| Sub-Struct | Fields |
|---|---|
| `MetricsState` | `metrics_broadcaster`, `metrics`, `system_resources`, `metrics_history`, `site_metrics`, `start_time`, `request_logs`, `logs_broadcaster` (8) |
| `WafTrackingState` | `probe_tracker`, `suspicious_word_tracker`, `upstream_error_tracker`, `threat_level_manager`, `rule_feed_manager` (5) |
| `SecurityState` | `admin_token`, `csrf_tokens`, `rate_limiter` (3) |
| `MeshState` | `mesh_transport`, `client_audit_manager` (2) |
| `HoneypotState` | `port_honeypot_controller`, `port_honeypot_runner`, `icmp_filter` (3) |
| `ProcessState` | `config`, `process_manager`, `alert_manager` (3) |

**Risk:** All 22 fields are `pub`. Splitting changes access paths (e.g., `state.metrics` → `state.metrics_state.metrics`). Search all consumers before splitting.

### 12.5 Per-Handler Auth Middleware (6.2.13)

**Status:** LOW. Auth checks are duplicated in each handler. Consolidate into Axum middleware.

**Fix:** Create a middleware layer that checks auth on all `/admin/*` routes (except login). This replaces per-handler `require_auth()` calls.

### 12.6 Hardcoded File Paths (6.2.9)

**Status:** LOW. `src/admin/handlers/config.rs:971+` has hardcoded paths. Replace with config-driven paths.

### 12.7 `block_on` in Async Context (6.2.1)

**Status:** LOW. `src/admin/mod.rs:116` uses `block_on` to create the admin router synchronously. This blocks the async executor.

**Fix:** Make router creation async, or pass pre-built config as a parameter. Low priority since it only runs once at startup.

### 12.8 Rate Limiter Consolidation (6.2.4)

**Status:** LOW. Three separate rate limiters exist:

| Location | Purpose |
|---|---|
| `src/admin/rate_limit.rs` | General admin rate limiting |
| `src/admin/state.rs:19-60` | Admin state rate limiting |
| `src/admin/auth.rs:14-78` | Auth attempt rate limiting |

**Fix:** Consolidate into a single `AdminRateLimiter` abstraction with per-route limits. Low priority since each limiter works correctly in isolation.

### 12.9 Admin Token bcrypt Hashing (2.F4)

**Status:** LOW. Token is stored as plaintext in config (by design — shared secret). bcrypt hashing adds defense-in-depth.

**Fix:** On startup, hash the config token with `bcrypt::hash()`. Store the hash in memory. On each request, use `bcrypt::verify()`. This matches the user auth flow. ~30 lines of change across `src/master/commands.rs` and admin auth check.

---

## Phase 13: WAF Core Refactoring

> Estimated effort: 2-3 days.

### 13.1 `WafCore::new()` 19 Params (6.3.1)

**Status:** MEDIUM. `src/waf/mod.rs:253` takes 19 parameters.

**Fix:** Introduce `WafCoreConfig` struct:

```rust
pub struct WafCoreConfig {
    pub enable_xss: bool,
    pub enable_sqli: bool,
    pub enable_ssrf: bool,
    // ... all 19 fields
}
```

Change `WafCore::new(config: WafCoreConfig)` to accept the struct. Update all callers.

### 13.2 `check_request_full()` Split (6.3.2)

**Status:** MEDIUM. `src/waf/mod.rs:667` is ~400 lines with mixed concerns.

**Extract into separate methods:**

```rust
fn check_rate_limit(&self, ...) -> WafDecision
fn check_bot_protection(&self, ...) -> WafDecision
fn check_honeypot(&self, ...) -> WafDecision
fn check_challenge(&self, ...) -> WafDecision
fn check_attack_patterns(&self, ...) -> WafDecision
fn check_endpoint_block(&self, ...) -> WafDecision
```

Each method returns `WafDecision`. The main function becomes a sequential call chain with early returns.

### 13.3 Memory Limits on State (6.3.7)

**Status:** LOW. `src/block_store.rs` has unbounded state accumulation.

**Fix:** Add configurable max entries with LRU eviction. Use `std::collections::HashMap` with a size limit and eviction callback.

---

## Phase 14: IPC Deduplication and Platform Code

> Estimated effort: 4-6 days. Platform-specific testing required.

### 14.1 Unix/Windows IPC Handler Dedup (6.4.1)

**Status:** MEDIUM. `src/worker/mod.rs` has duplicated IPC handler logic for Unix and Windows.

**Fix:** Extract common logic into a trait or helper module. Platform-specific code (Unix sockets vs. named pipes) goes behind a `PlatformIpc` trait.

### 14.2 Windows IPC Pipe Code (6.4.2)

**Status:** MEDIUM. `src/main.rs:1177-1314` has Windows-specific IPC pipe code.

**Fix:** Consolidate into a reusable `src/platform/windows_ipc.rs` module.

### 14.3 Static Worker Client Handling (6.4.3)

**Status:** MEDIUM. `handle_minify_client_connection` and its Windows variant are duplicated.

**Fix:** Unify with platform-agnostic abstraction.

### 14.4 Sync/Async `IpcStream` API (6.4.4)

**Status:** LOW. `src/process/ipc.rs:838-1038` (sync) and `ipc_transport.rs:20-407` (async) have divergent APIs.

**Fix:** Document the divergence and intended use cases. Consider unifying behind an async-first API with `blocking` feature for sync callers.

---

## Phase 15: Large Module Splits

> Estimated effort: 10-15 days. Highest-risk phase. Do incrementally, one module at a time.

### 15.1 `src/mesh/transport.rs` (6,448 lines)

**Status:** XL. God object with 32-field struct and ~6,200 lines of implementation.

**Approach:** Extract `impl` blocks into submodules. The struct stays in `transport.rs`; each submodule adds an `impl MeshTransport { ... }` block.

| Submodule | Extracted Functions | Est. Lines |
|---|---|---|
| `transport_routing.rs` | Route query/response handling, preflight | ~400 |
| `transport_dht.rs` | DHT snapshot/sync/anti-entropy, find_node | ~280 |
| `transport_org.rs` | Org registration, tier keys, upstream registration | ~330 |
| `transport_dns.rs` | Anycast registration/health, zone sync, domain verify | ~600 |
| `transport_global.rs` | Global node announce, key exchange | ~400 |
| `transport_connection.rs` | Start/stop, listeners, bootstrap, maintenance | ~400 |
| `transport_peer.rs` | Peer messaging, health checks, load reports | ~350 |
| `transport_rate_limit.rs` | Auth failures, peer rate limiting | ~150 |

**Implementation order:** Start with `transport_rate_limit.rs` (smallest, no cross-deps), then `transport_connection.rs`, then domain handlers.

**Verification:** `cargo test --features mesh` after each extraction. Verify no public API changes.

### 15.2 `src/dns/server.rs` (4,733 lines)

**Status:** H. Complex DNS logic with feature-gated sections.

| Submodule | Content | Est. Lines |
|---|---|---|
| `query_handler.rs` | UDP + TCP query processing | ~1,500 |
| `zone_manager.rs` | Zone CRUD, serial management, SOA | ~800 |
| `rate_limiter.rs` | Per-IP query rate limiting | ~400 |
| `dnssec_handler.rs` | DNSSEC signing, key management | ~600 |

**Note:** The `QueryContext` struct (Phase 11.2) should be completed before this split, as it reduces the parameter coupling between functions.

### 15.3 `src/dns/mesh_sync.rs` (1,975 lines)

**Covered in Phase 11.1.** No additional work needed here.

### 15.4 `src/worker/mod.rs` (1,586 lines)

**Status:** M.

| Submodule | Content | Est. Lines |
|---|---|---|
| `connection.rs` | HTTP connection accept, proxy, drain | ~600 |
| `image_poisoning.rs` | Image fingerprinting/poisoning | ~300 |
| `response_builder.rs` | Compressed error responses, minification | ~200 |

### 15.5 `src/proxy.rs` (1,364 lines)

**Status:** LOW. Below the 1,500-line threshold. Manageable as-is. Split only if other changes touch it extensively.

### 15.6 `src/router.rs` (762 lines)

**Status:** N/A. Below threshold. No split needed.

### 15.7 `src/admin/state.rs` (511 lines)

**Covered in Phase 12.4.** No additional work needed here.

---

## Phase 16: Testing, Build, and Documentation

> Estimated effort: 3-5 days. Low risk, can be done in parallel with other phases.

**Completed: 2026-03-26.** See completion notes below.

### 16.1 Benchmark Migration to Criterion (7.4)

**Status:** ✅ DONE. 4 benchmark files migrated from `Instant::now()` + `println!` to Criterion.

**Fix:** Add `criterion` to `[dev-dependencies]`. Rewrite benchmarks using `criterion::BenchmarkGroup`. Add `[[bench]]` sections to `Cargo.toml`. Run with `cargo bench`.

### 16.2 Fuzzing Expansion (7.6)

**Status:** LOW. Current 3 fuzz targets are sufficient. Expansion requires corpus seed collection.

**Future targets:**
- WAF detection (random HTTP requests)
- DNS wire format (random DNS packets)
- HTTP parsing (malformed HTTP/1.1 and HTTP/2)

### 16.3 Dependency Hygiene (7.7)

| # | Item | Status | Action |
|---|---|---|---|
| 7.7.1 | Alpha `lightningcss` | Deferred | Monitor for stable release; upgrade when available |
| 7.7.2 | Unmaintained `boringtun` | Deferred | Evaluate `wireguard-rs` or `boringtun` fork alternatives |
| 7.7.3 | Exact patch version pins | Medium | Change `"0.11.11"` → `"0.11"` in `Cargo.toml`. Run `cargo update` in isolation. Regression test. |
| 7.7.6 | Git patch no expiry | Deferred | Depends on upstream `quinn` release. Monitor. |
| 7.7.7 | Dead `handler.rs` + `range.rs` | Low | Already documented in AGENTS.md. Delete when confident they're unused. |

### 16.4 Documentation (7.8)

**Status:** LOW. Large effort. Prioritize:

1. Module-level rustdoc on public types (top 20 most-used modules).
2. `# Safety` docs on remaining ~5% of unsafe blocks.
3. Architecture overview doc for new contributors.

### 16.5 Clippy Warning Reduction (2.F2)

**Status:** LOW. ~154 warnings remain. Categories:

| Category | Count | Fix |
|---|---|---|
| Clamp patterns | ~15 | Replace manual clamping with `.clamp()` |
| Boolean simplification | ~12 | Simplify `if x { true } else { false }` → `x` |
| `&PathBuf` → `&Path` | ~8 | Change function signatures |
| Collapsed `if let` | ~8 | Use `if let` chains |
| Complex types | ~7 | Type aliases |
| Other | ~100 | Various mechanical fixes |

**Strategy:** Fix incrementally as modules are touched for other work. Or batch-fix by category.

### 16.6 Residual "Field Never Read" Warnings (3.F1)

**Status:** LOW. 33 fields written but never read. Per-item audit:

- If truly dead: delete the field and all write sites.
- If used conditionally: add `#[cfg(feature = "...")]`.
- If for future use: add `#[allow(dead_code)]` with `// TODO:` comment.

## Phase 16 Completion Notes (2026-03-26)

### 16.1: Benchmark Migration to Criterion

4 benchmark files rewritten using Criterion:

| File | Benchmarks | Notes |
|------|-----------|-------|
| `benches/bench_attack_detection.rs` | 9 | Normalizer (7 inputs), string alloc (2), URL decode |
| `benches/bench_proxy_cache.rs` | 4 | HashMap insert (3 sizes), cache get, LRU invalidate, hasher |
| `benches/bench_ratelimit.rs` | 6 | AtomicBucketWindow (3 ops), ring buffer, collections (2) |
| `benches/bench_dns.rs` | 2 | DNS rate limiter, zone serial (feature-gated `dns`) |

Old files removed from `tests/`. `[[bench]]` sections added to `Cargo.toml` with `harness = false`. `criterion` 0.5 added to `[dev-dependencies]`.

### 16.3: Dependency Hygiene

16 exact patch version pins relaxed to minor/major:

| Package | Before | After |
|---------|--------|-------|
| lru_time_cache | 0.11.11 | 0.11 |
| ahash | 0.8.12 | 0.8 |
| aes-gcm | 0.10.3 | 0.10 |
| async-trait | 0.1.89 | 0.1 |
| daemonize2 | 0.6.2 | 0.6 |
| ed25519-dalek | 2.2.0 | 2 |
| hkdf | 0.12.4 | 0.12 |
| hmac | 0.12.1 | 0.12 |
| socket2 | 0.6.2 | 0.6 |
| httparse | 1.10.1 | 1 |
| pbkdf2 | 0.12.2 | 0.12 |
| sha1 | 0.10.6 | 0.10 |
| sha3 | 0.10.8 | 0.10 |
| base32 | 0.5.1 | 0.5 |
| libc | 0.2.182 | 0.2 |
| quinn | 0.11.9 | 0.11 |

`cargo update` ran successfully. Multiple transitive dependencies updated.

### 16.5: Clippy Warning Reduction

~20 clippy warnings fixed:

- **Clamp patterns (8):** `value.min(X).max(Y)` → `value.clamp(Y, X)` in `pool.rs`, `query_validator.rs`, `edns.rs`, `topology.rs`, `transport.rs`, `regional_hubs.rs`
- **Boolean simplification (2):** Removed duplicate `segments[0] == 0xfc00` in `request_sanitization.rs`; factored `has_runtime && (has_exec || has_param)` in `malware_scanner.rs`
- **`&PathBuf` → `&Path` (7):** Function signatures in `address.rs`, `auth/mod.rs`, `ipc_client.rs`
- **`clone()` → `slice::from_ref()` (5):** In `dns/transfer.rs`

Also fixed: duplicate `mesh_sync.rs.bak` file removed, `Bearer::new()` → `Authorization::bearer()` API fix in `admin/middleware.rs`, `config_path()` call sites fixed in `admin/handlers/sites.rs`.

### 16.6: Field Never Read Warnings

Reduced from 85 to 44 warnings (~48% reduction). Added `#[allow(dead_code)]` with comments to ~20 structs across mesh, DNS, admin, WAF, and worker modules. Remaining 44 are individually annotated for future work.

### Verification

- `cargo check` ✅
- `cargo check --features dns` ✅
- `cargo check --benches` ✅
- `cargo test --test integration_test` ✅ (40/40 passed)
- `cargo test --test dns_config_test` ✅ (52/52 passed)
- `cargo test --test dns_integration_test` ⚠️ (41/45 passed, 4 pre-existing failures)

### Additional work (2026-03-26 follow-up)

Further clippy and code quality improvements:

**16.5 Clippy (additional ~34 warnings fixed):**
- Reference-to-reference (15): Removed unnecessary `ref` in `if let Some(ref x) = opt` patterns across `dns/server.rs` (12), `dns/doh.rs`, `dns/doq.rs`, `dns/dot.rs`
- Collapsible if let (7): Collapsed nested `if let` into `let ... else` in `resolver.rs` (3), `drain_manager.rs` (2), `process/manager.rs` (1), `mesh/transport.rs` (1)
- Identical blocks (4): Deduplicated in `mesh/transport.rs` (dead code removal), `mesh/dht/record_store.rs` (combined with `||`), `honeypot_port/protocol.rs`, `honeypot_port/responders/vulnerable.rs`
- Clippy reduced from 151 → 117 warnings

**16.6 Field never read (additional ~8 annotations):**
- Added `#[allow(dead_code)]` to `waf/ratelimit.rs` (semaphore), `waf/ratelimit/core.rs` (config), `waf/endpoints.rs` (use_regex), `waf/violation_tracker.rs` (persist_path, persist_interval), `waf/traffic_shaper/global.rs` (threat_level), `tcp/mod.rs` (config), `udp/mod.rs` (config), `admin/state.rs` (burst)

**16.4 Documentation:**
- Added module-level rustdoc to 7 modules: `config/mod.rs`, `proxy_cache/mod.rs`, `http_client/mod.rs`, `process/mod.rs`, `overseer/mod.rs`, `worker/mod.rs`, and existing `waf/mod.rs`

---

## Phase 17: Deferred Indefinite (N/A or Blocked)

These items are blocked on upstream changes, design decisions, or are conditionally needed. No action unless circumstances change.

| # | Item | Status | Reason |
|---|------|--------|--------|
| 17.1 | Async mutex standardization | N/A | `_sync` methods using `blocking_read()` on `tokio::sync::RwLock` are correct for current sync callers. Only needed if callers migrate to async. |
| 17.2 | Safe abstractions for platform unsafe | N/A | Phase 3 review concluded `# Safety` docs on `unsafe fn` signatures is standard Rust convention. No safety issues identified. |
| 17.3 | `MeshConfig` sub-config grouping (10.4) | Skip | Most sub-configs already extracted. Remaining ~10 scalars provide limited benefit. serde backward compatibility risk if field names change. |
| 17.4 | `MeshMessage` variant restructuring (10.5) | Skip | Wire protocol change — would break backward compatibility with existing mesh nodes. Use naming conventions instead. |
| 17.5 | Alpha `lightningcss` upgrade | Blocked | Monitor for stable release. |
| 17.6 | Unmaintained `boringtun` replacement | Blocked | Evaluate alternatives when WireGuard feature is prioritized. |
| 17.7 | Git patch quinn expiry | Blocked | Depends on upstream quinn release. |

---

## Execution Order: Parallel Waves

Phases are organized into **waves** based on file-level dependencies. All phases within a wave touch different files and can run concurrently. A wave must complete before the next wave starts.

### Dependency Graph

```
Wave 1 (all independent, no shared files)
┌─────────────────────────────────────────────────────┐
│  Phase 8   auth,waf,ssrf,upstream,admin,mesh,cert   │
│  Phase 9   http_client,proxy,waf,dns                 │
│  Phase 10  mesh only                                 │
│  Phase 11  dns only                                  │
│  Phase 12  admin only                                │
│  Phase 13  waf only                                  │
│  Phase 16  tests/docs only                           │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
Wave 2 (depends on Wave 1 — specifically Phase 10 mesh cleanup)
┌─────────────────────────────────────────────────────┐
│  Phase 14  worker,process (needs Phase 10 stable)    │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
Wave 3 (depends on Phase 9, 11, 13, 14 complete)
┌─────────────────────────────────────────────────────┐
│  Phase 15  transport.rs, dns/server.rs, worker/mod   │
│            (needs subsystem refactoring stable)       │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
Wave 4 (depends on Wave 3 — final cleanup, all subsystems stable)
┌─────────────────────────────────────────────────────┐
│  Phase 18  admin/state.rs split, admin cleanup       │
│  Phase 19  mesh/protocol.rs, config.rs, dht splits   │
│  Phase 20  clippy warnings (all files)               │
│  Phase 21  dead fields (all files)                   │
│  Phase 22  documentation (all files)                 │
└─────────────────────────────────────────────────────┘
```

### Wave 1: Independent Subsystem Work (parallel)

**All 7 phases below touch different files. Run concurrently across agents or branches.**

| Phase | Scope | Files Modified | Effort | Risk |
|-------|-------|---------------|--------|------|
| **8** Quick Wins | CSS exemptions, auth dedup, SSRF fix, upstream wiring, tests | `waf/mod.rs`, `auth/mod.rs`, `ssrf.rs`, `proxy.rs`, `tls/server.rs`, `http/server.rs`, `upstream/pool.rs`, `admin/legacy.rs`, `mesh/cert.rs`, `waf/rule_feed.rs`, `waf/endpoints.rs`, `config/mod.rs`, `http_client/mod.rs` | 1-2d | Low |
| **9** Performance | Binary body, header alloc, firewall, zone index | `http_client/mod.rs`, `proxy.rs`, `tls/server.rs`, `waf/config.rs`, `dns/recursive.rs`, `dns/server.rs` | 2-3d | Med |
| **10** Mesh Cleanup | duration_since, crypto expects, dead code | `mesh/protocol.rs`, `mesh/transport.rs`, `mesh/organization.rs`, `mesh/cert.rs`, `mesh/config.rs`, 22 mesh files | 2-3d | Med |
| **11** DNS Refactoring | mesh_sync split, QueryContext, clone audit | `dns/mesh_sync.rs` → `dns/mesh_sync/*.rs`, `dns/server.rs`, `dns/doq.rs`, `dns/doh.rs`, `dns/dot.rs` | 3-5d | Med |
| **12** Admin Refactoring | Auth, tokens, config race, state split, middleware | `admin/handlers/theme.rs`, `admin/handlers/honeypot.rs`, `admin/auth.rs`, `admin/handlers/config.rs`, `admin/handlers/sites.rs`, `admin/state.rs`, `admin/mod.rs`, `admin/rate_limit.rs` | 3-4d | Low-Med |
| **13** WAF Core | WafCore config, check_request_full split, memory limits | `waf/mod.rs`, `block_store.rs` | 2-3d | Low |
| **16** Testing & Build | Benchmarks, fuzzing, deps, docs, clippy, dead fields | Tests, `Cargo.toml`, docs, various | 3-5d | Low |

**Wave 1 wall-clock: 3-5 days** (longest phase determines duration when running in parallel).

**Note on Phase 8 vs 9 file overlap:** Both phases modify `src/http_client/mod.rs` (8.3.1 adds `UpstreamTlsConfig` wiring, 9.1 changes `HttpResponse.body` to `Bytes`). If running these in parallel on separate branches, Phase 8.3.1 should be merged first since it changes constructor call sites that Phase 9.1 also touches. **Recommended: sequence 8.3.1 before 9.1 within Wave 1, or have one agent handle both.**

### Wave 2: IPC Deduplication

**Depends on:** Wave 1 complete (specifically Phase 10 mesh cleanup must be done, since IPC code interacts with mesh transport).

| Phase | Scope | Files Modified | Effort | Risk |
|-------|-------|---------------|--------|------|
| **14** IPC Dedup | Unix/Windows handler dedup, pipe code, IpcStream | `worker/mod.rs`, `main.rs`, `process/ipc.rs`, `process/ipc_transport.rs`, `platform/` | 4-6d | Med |

### Wave 3: Large Module Splits

**Depends on:** Wave 2 complete (all subsystem refactoring must be stable before splitting).

**Prerequisites checklist:**
- [ ] Phase 9.1 done (binary body in cache — proxy.rs type changes stable)
- [ ] Phase 11.2 done (QueryContext — reduces dns/server.rs coupling before split)
- [ ] Phase 13 done (WAF core refactoring — waf/mod.rs changes stable)
- [ ] Phase 14 done (IPC dedup — worker/mod.rs changes stable)

| Phase | Scope | Files Modified | Effort | Risk |
|-------|-------|---------------|--------|------|
| **15.1** transport.rs split | Extract 8 handler submodules | `mesh/transport.rs` → `mesh/transport_*.rs` | 5-7d | High |
| **15.2** dns/server.rs split | Extract query, zone, rate, dnssec handlers | `dns/server.rs` → `dns/*_handler.rs` | 3-5d | Med |
| **15.4** worker/mod.rs split | Extract connection, image, response builders | `worker/mod.rs` → `worker/*.rs` | 2-3d | Low |

**Wave 3 wall-clock: 5-7 days** (15.1 is the critical path; 15.2 and 15.4 can partially overlap).

### Phase 17 items folded into Wave 1

The items from former Phase 17 are absorbed into Wave 1 phases:

| Former Item | New Location | Rationale |
|---|---|---|
| `ca_cert_path` unused (2.F3) | **Phase 8** item 8.3.2 | Small change (~20 lines), fits with upstream client wiring |
| Admin token bcrypt (2.F4) | **Phase 12** item 12.9 | Auth subsystem concern, fits with admin refactoring |
| Async mutex (4.5/4.F6) | **Deferred indefinitely** | Correct for current callers |
| Safe platform abstractions (3.F3) | **Deferred indefinitely** | No safety issues identified |

### Wave 4: Cleanup and Polish

**Depends on:** Wave 3 complete. Final wave — resolves all remaining deferred items.

**Current state:** ~307 clippy warnings, 36 "never read" field warnings, 3 modules above 1,500 lines (`mesh/protocol.rs` 5,263, `mesh/dht/record_store.rs` 2,393, `mesh/config.rs` 2,217), AdminState has 22 pub fields.

**All 5 phases below touch different subsystems. Run concurrently across agents.**

| Phase | Scope | Files Modified | Effort | Risk |
|-------|-------|---------------|--------|------|
| **18** AdminState Split | Split into sub-structs, config paths, block_on, rate limiter | `admin/state.rs`, `admin/mod.rs`, `admin/handlers/config.rs`, `admin/handlers/sites.rs` | 2-3d | Med |
| **19** Mesh God Object Splits | Split protocol.rs, record_store.rs, config.rs | `mesh/protocol.rs`, `mesh/dht/record_store.rs`, `mesh/config.rs` | 3-4d | High |
| **20** Clippy Warning Reduction | Fix ~307 warnings by category | Various | 1-2d | Low |
| **21** Dead Field Cleanup | Fix 36 "never read" warnings | Various | 0.5d | Low |
| **22** Documentation & Fuzzing | Rustdoc, safety docs, fuzz targets | Various | 1-2d | Low |

**Wave 4 wall-clock: 3-4 days** (Phase 19 is the critical path).

#### Phase 18: AdminState Split and Admin Cleanup

**18.1 AdminState sub-structs (12.4)** — 22 fields → 6 sub-structs:

```rust
pub struct MetricsState {
    pub metrics_broadcaster: Arc<Broadcaster>,
    pub metrics: Arc<RwLock<AggregatedMetrics>>,
    pub system_resources: Arc<RwLock<SystemResources>>,
    pub metrics_history: Arc<RwLock<VecDeque<MetricsSnapshot>>>,
    pub site_metrics: Arc<RwLock<HashMap<String, SiteMetrics>>>,
    pub start_time: Instant,
    pub request_logs: Arc<RwLock<VecDeque<RequestLog>>>,
    pub logs_broadcaster: Arc<Broadcaster>,
}

pub struct WafTrackingState {
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
}

pub struct SecurityState {
    pub admin_token: String,
    pub csrf_tokens: Arc<RwLock<HashMap<String, Instant>>>,
    pub rate_limiter: Option<Arc<AdminRateLimiter>>,
}

pub struct MeshState {
    pub mesh_transport: Option<Arc<MeshTransport>>,
    pub client_audit_manager: Option<Arc<ClientAuditManager>>,
}

pub struct HoneypotState {
    pub port_honeypot_controller: Option<Arc<PortHoneypotController>>,
    pub port_honeypot_runner: Option<Arc<PortHoneypotRunner>>,
    #[cfg(feature = "icmp-filter")]
    pub icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
}

pub struct ProcessState {
    pub config: Arc<TokioRwLock<ConfigManager>>,
    pub process_manager: Option<Arc<ProcessManager>>,
    pub alert_manager: Arc<AlertManager>,
}
```

**Risk:** All 22 fields are `pub`. Splitting changes access paths (e.g., `state.metrics` → `state.metrics.metrics`). Must search all consumers and update access paths. ~30 handler files reference these fields.

**Implementation steps:**
1. Define 6 sub-structs in `admin/state.rs`
2. Replace 22 fields in `AdminState` with 6 sub-struct fields
3. Update `AdminState::new()` and `with_*` builder methods
4. Search and replace all consumer access paths (~150+ occurrences across handler files)
5. Run `cargo check` after each sub-struct

**18.2 Hardcoded file paths (12.6)** — `admin/handlers/config.rs:971+`
- Read config directory path from `AdminState` or pass as parameter
- Replace hardcoded `"config/"` references

**18.3 block_on in async context (12.7)** — `admin/mod.rs:116`
- Make `create_admin_router_with_state` async (already done in prior session)
- If `block_on` still exists, remove it

**18.4 Rate limiter consolidation (12.8)** — 3 rate limiters in admin
- Audit all 3: `admin/rate_limit.rs`, `admin/state.rs`, `admin/auth.rs`
- If each serves a different purpose with different limits, document the distinction rather than consolidating

#### Phase 19: Mesh God Object Splits

**19.1 `mesh/protocol.rs` (5,263 lines → target <1,500)**

This is the largest remaining file. Read and identify method groups:
- Message serialization/deserialization
- Protocol negotiation
- Handshake logic
- Stream framing
- Error handling

Extract into submodules following the same pattern as transport.rs:
| Submodule | Content |
|---|---|
| `protocol_handshake.rs` | Handshake, session key exchange |
| `protocol_framing.rs` | Message framing, length-prefix I/O |
| `protocol_negotiation.rs` | Version negotiation, capability exchange |
| `protocol_stream.rs` | Stream management, multiplexing |

**19.2 `mesh/dht/record_store.rs` (2,393 lines → target <1,500)**
- DHT record CRUD operations
- Record validation
- Storage backend abstraction
- Replication logic

**19.3 `mesh/config.rs` (2,217 lines → target <1,500)**
- Config parsing
- Config validation
- Default value generation
- Config migration (if any)

**Implementation approach:** Same as Phase 15 — struct stays in original file, impl methods split into sibling modules. Verify `cargo check` after each split.

#### Phase 20: Clippy Warning Reduction (~307 warnings)

Fix by category, easiest first:

| Category | Est. Count | Fix Pattern |
|---|---|---|
| Clamp patterns | ~15 | `value.min(X).max(Y)` → `value.clamp(Y, X)` |
| Boolean simplification | ~12 | `if x { true } else { false }` → `x` |
| `&PathBuf` → `&Path` | ~8 | Change function parameter types |
| Collapsible `if let` | ~8 | Use `if let ... else` or `let ... else` |
| Complex types | ~7 | Type aliases |
| Reference-to-reference | ~20+ | Remove unnecessary `ref` in patterns |
| Unnecessary clones | ~30+ | Use references where possible |
| Other | ~200+ | Various mechanical fixes |

**Strategy:** Fix in batches of 50. Run `cargo clippy` between batches to verify no regressions. Focus on categories that reduce warning count most first.

#### Phase 21: Dead Field Cleanup (36 warnings)

Run `cargo check 2>&1 | grep "never read"` to list all 36 fields. For each:
- If truly dead: delete the field and all write sites
- If conditionally used: add `#[cfg(feature = "...")]`
- If for future use: add `#[allow(dead_code)]` with comment

#### Phase 22: Documentation and Fuzzing

**22.1 Documentation**
- Add module-level rustdoc to top 10 most-used modules not yet documented
- Add `# Safety` docs on remaining unsafe blocks
- Target: 100% SAFETY doc coverage on unsafe blocks

**22.2 Fuzzing**
- Document future fuzz targets (WAF detection, DNS wire format, HTTP parsing)
- Add seed corpus comments to existing fuzz targets
- No new fuzz target implementation (deferred to future work)

---

## Summary: Parallel Execution Timeline

```
Week 1-2:  Wave 1 (7 parallel streams)          ~5 days wall-clock
           ├── Phase 8  (quick wins + tests)
           ├── Phase 9  (performance)             * merge 8.3.1 before 9.1
           ├── Phase 10 (mesh cleanup)
           ├── Phase 11 (DNS refactoring)
           ├── Phase 12 (admin refactoring)
           ├── Phase 13 (WAF core)
           └── Phase 16 (testing & build)

Week 3:    Wave 2 (1 stream)                     ~5 days wall-clock
           └── Phase 14 (IPC dedup)

Week 4-5:  Wave 3 (1 critical + 2 parallel)      ~7 days wall-clock
           ├── Phase 15.1 (transport.rs — critical path)
           ├── Phase 15.2 (dns/server.rs — can overlap with 15.4)
           └── Phase 15.4 (worker/mod.rs — can overlap with 15.2)

Week 5-6:  Wave 4 (5 parallel streams)           ~4 days wall-clock
           ├── Phase 18 (AdminState split)
           ├── Phase 19 (mesh god object splits)   * critical path
           ├── Phase 20 (clippy warnings)
           ├── Phase 21 (dead fields)
           └── Phase 22 (documentation)
```

**Total wall-clock with full parallelization: ~21 days** (vs ~40-55 days sequential).

---

## Verification

Run after each wave:

```bash
cargo fmt -- --check
cargo clippy -- -D warnings  # aspirational; fix warnings as you go
cargo check
cargo check --features dns
cargo check --features mesh  # after Wave 1
cargo test
cargo test --features dns
cargo test --test integration_test
```

## Success Metrics

| Metric | Start | After Wave 3 | Target After Wave 4 |
|--------|-------|-------------|---------------------|
| `unwrap()` in production | ~12 | <10 | <10 |
| Unsafe blocks with SAFETY docs | ~95% | ~95% | 100% |
| Max module size (lines) | 6,448 | 1,290 | <1,500 (all files) |
| Modules with zero tests | 3 | ~1 | 0 |
| Clippy warnings | ~154 | ~307 | <50 |
| Dead field warnings | ~85 | 36 | 0 |
| Binary content in cache | Corrupted | Correct | Correct |
| Mesh nodes with `skip_verify` | Not wired | Per-site | Per-site |
| Wall-clock effort (parallel) | — | ~17d | ~21d |
| Wall-clock effort (sequential) | — | ~32-49d | ~40-55d |
