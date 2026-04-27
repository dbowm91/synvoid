# MaluWAF Implementation Plan

**Status**: Active - Implementation Phase
**Last Updated**: 2026-04-27
**Verification Completed**: 2026-04-27 (all items verified against codebase)

---

## Completed Waves

These waves have been implemented and verified. Details are recorded in AGENTS.md under "Recently Completed Items."

| Wave | Feature | Date |
|------|---------|------|
| 1.1 | Streaming WAF Engine (`StreamingWafCore`, `StreamingWafDecision`) | 2026-04-27 |
| 1.2 | DHT Neighborhood Persistence (`record_store_persist.rs`) | 2026-04-27 |
| 2.1 | Hybrid Post-Quantum Mesh Signatures (`HybridSignature`, `ml_dsa.rs`) | 2026-04-27 |
| 2.2 | Windows Service & DX (`WindowsInterfaceResolver`, firewall rules) | 2026-04-27 |
| 3.1 | Federated Behavioral Intelligence (`BehavioralIntelligenceManager`) | 2026-04-27 |
| 3.2 | Real-time Topology Visualizer (`/api/mesh/topology`, `/api/mesh/topology/graph`) | 2026-04-27 |

---

## Remaining Work: Wave Organization

The remaining work is organized into **waves** designed for parallel execution by sub-agents. Each wave can be worked on independently. Within a wave, individual items are independent unless noted.

**Dependency graph:**
```
Wave 4 (Critical Security)
    ↓
Wave 5 (High Priority Functional) ← parallel with → Wave 6 (Performance)
    ↓
Wave 7 (Code Quality & Cleanup) ← parallel with → Wave 8 (Admin API & DX)
    ↓
Wave 9 (Testing) ← parallel with → Wave 10 (Documentation)
    ↓
Wave 11 (New Features - after mesh functional)
```

Waves 5+6 can run in parallel. Waves 7+8 can run in parallel. Within each wave, ALL items can be assigned to different sub-agents simultaneously.

---

## Wave 4: Critical Security Fixes

**Gate**: Must complete before Waves 5-11. Fixes active security vulnerabilities and a critical dependency vulnerability.

### Group A: Independent fixes (assign to separate sub-agents)

#### P0.5: Time-based challenge verification bypass

**Severity**: CRITICAL
**File**: `src/mesh/security_challenge.rs:159-190`
**Est**: 2h

**Problem**: `verify_time_based_challenge()` takes `_solution: &str` (underscore = unused). It only checks the challenge exists (line 162) and hasn't expired (line 170), then marks it verified (line 177). Any string is accepted as the solution.

**Fix**: Implement actual solution verification. The challenge should store expected solution parameters (e.g., hash of expected answer) at creation time, and verify against them. Look at how `verify_pow_challenge()` works in `src/challenge/pow.rs` for the pattern.

**Verification**: `cargo test --lib -- security_challenge`

---

#### P0.6: Pass-over fallback signing violation

**Severity**: CRITICAL
**File**: `src/mesh/passover_key_exchange.rs:469-534`
**Est**: 1h

**Problem**: When origin is unreachable, the fallback path (lines 481-534) uses `origin_signing_key` to sign (lines 505-515). A global node configured with `origin_signing_key` will produce messages appearing signed by an origin node, violating the trust chain.

**Fix**: In the fallback path, if `self.node_role.is_global()`, sign with the global key instead. Do NOT use `origin_signing_key` unless the node actually IS an origin. Add a role check before the fallback signing path.

**Verification**: `cargo test --lib -- passover`

---

#### P0.7: RecordStoreManager clone creates empty store

**Severity**: CRITICAL
**File**: `src/mesh/dht/record_store.rs:468-519`
**Est**: 2h

**Problem**: `Clone` impl at line 475 uses `records: ShardedRecordStore::new()` instead of cloning from `self.records`. All other fields are properly cloned. Cloned managers have zero records, causing data loss.

**Fix**: Replace `ShardedRecordStore::new()` with proper clone of `self.records`. Check if `ShardedRecordStore` has a `clone()` method; if not, iterate and insert records from the source.

**Verification**: `cargo test --lib -- record_store`

---

#### P0.1: WASM `table_growing` unbounded

**Severity**: CRITICAL
**File**: `src/plugin/wasm_runtime.rs:319-326`
**Est**: 1-2h
**Depends on**: None (can run parallel with P0.5-P0.7)

**Problem**: `table_growing()` returns `Ok(true)` unconditionally at line 325. Meanwhile `memory_growing()` at line 316 properly checks `Ok(desired <= self.max_memory)`. Tables can grow without bound.

**Fix**: Add a `max_table_elements` limit (similar to `max_memory`). Check `desired` against the limit. Return `Ok(false)` if exceeded. Add config field for the limit.

**Verification**: `cargo test --lib -- wasm_runtime`

---

#### P0.2: WASM pool DHT prefix leakage

**Severity**: CRITICAL
**File**: `src/plugin/instance_pool.rs:148-159`
**Est**: 2-3h
**Depends on**: None

**Problem**: `prepare_for_request()` at line 148 resets `start`, `timeout`, and `env` but does NOT reset `allowed_dht_prefixes`. A previous request's tenant DHT prefixes persist across pool reuse, leaking access between tenants.

**Fix**: In `prepare_for_request()`, add `self.allowed_dht_prefixes = self.default_allowed_dht_prefixes.clone()` (or reset to empty if no defaults). Ensure the pool instance is fully sanitized between requests.

**Verification**: `cargo test --lib -- instance_pool`

---

#### P0.3: Threat intel signer bypass

**Severity**: CRITICAL
**File**: `src/mesh/threat_intel.rs:1606-1621`
**Est**: 30m
**Depends on**: None

**Problem**: Line 1607: `if !self.node_role.is_global() && !self.config.trusted_signers.is_empty()` — when `trusted_signers` is empty, the condition short-circuits and ALL non-global nodes bypass the trusted signer check. Any non-global node can send forged threats.

**Fix**: Use deny-by-default: if `trusted_signers` is empty and the node is not global, REJECT. The condition should be:
```rust
if !self.node_role.is_global() {
    if self.config.trusted_signers.is_empty() {
        tracing::warn!("No trusted signers configured - rejecting threat from non-global node");
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
    if !self.config.trusted_signers.contains(&signer_public_key) {
        return Some(MeshMessage::ThreatAcknowledgement { accepted: false, ... });
    }
}
```

**Verification**: `cargo test --lib -- threat_intel`

---

#### P0.4: Serverless ignore limits

**Severity**: CRITICAL
**File**: `src/serverless/manager.rs:479-491,506-518`
**Est**: 30-60m
**Depends on**: None

**Problem**: `_limits` is constructed (lines 479-487 and 506-514) with underscore prefix (unused). `load_plugin_from_memory` (line 490) and `load_plugin` (line 517) are called WITHOUT passing the limits. Memory/CPU/timeout limits are computed and silently discarded.

**Fix**: Pass `limits` to the `load_plugin_from_memory` / `load_plugin` calls. Verify the function signatures accept a limits parameter (if not, add one). Remove the underscore prefix.

**Verification**: `cargo test --lib -- serverless`

---

#### P0.12: YARA trusted_signer global bypass

**Severity**: CRITICAL
**File**: `src/mesh/yara_rules.rs:942-954,1761-1812`
**Est**: 2h
**Depends on**: None

**Problem**: Two separate issues:
1. Lines 942-954 (DHT sync path): `if !self.config.trusted_signers.is_empty()` — no `is_global()` role check. When list is empty, ALL nodes bypass.
2. Lines 1761-1812 (announce path): Signature verification only, no trusted_signers authorization check at all.

**Fix**: Add `!self.node_role.is_global()` check like threat_intel has. Apply deny-by-default for empty trusted_signers list on non-global nodes. Add trusted_signers check to the announce path.

**Verification**: `cargo test --lib -- yara_rules`

---

#### P0.A: KyberSlash vulnerability (pqc_kyber → pqc_kyber_edit)

**Severity**: CRITICAL (RUSTSEC-2023-0079)
**Files**: `src/wasm_pow/Cargo.toml:30`, `src/wasm_pow/src/pqc.rs:6`
**Est**: 30m
**Depends on**: None

**Problem**: `pqc_kyber` 0.7.1 has timing side-channel in ML-KEM-768 division operations (CVSS 7.4). The fix fork `pqc_kyber_edit` 0.7.2 has identical API.

**Fix**:
1. In `src/wasm_pow/Cargo.toml`: Replace `pqc_kyber = { version = "0.7", features = ["wasm", "kyber768", "zeroize"] }` with `pqc_kyber_edit = { version = "0.7", features = ["wasm", "kyber768", "zeroize"] }`
2. In `src/wasm_pow/src/pqc.rs`: Replace `use pqc_kyber::*;` with `use pqc_kyber_edit::*;`

Keys generated with old crate are compatible (same algorithm).

**Verification**: `cargo check -p wasm-pow && cargo test -p wasm-pow`

---

### Group B: Depends on Group A items

#### P0.8: Severity-aware threat broadcast

**Severity**: CRITICAL
**File**: `src/mesh/threat_intel.rs:1507-1535`
**Est**: 1h
**Depends on**: P0.3 (signer bypass must be fixed first)

**Problem**: `broadcast_pending_threats()` broadcasts all threats uniformly with a fixed fanout factor. CRITICAL/HIGH severity threats should broadcast to 100% of peers for rapid propagation.

**Fix**: In `broadcast_pending_threats()`, check threat severity. For `Severity::Critical` and `Severity::High`, set fanout to all connected peers. For lower severities, keep the current probabilistic fanout.

**Verification**: `cargo test --lib -- threat_intel`

---

#### P0.9: Threat duplicate detection key mismatch

**Severity**: CRITICAL
**File**: `src/mesh/threat_intel.rs:831,1066,1165`
**Est**: 1h
**Depends on**: P0.8

**Problem**: Incoming mesh threats stored at raw key (line 831): `indicator.indicator_value.clone()` → `"1.2.3.4"`. Local threats stored at composite key (lines 1066, 1165): `make_indicator_key()` → `"threat_indicator:1.2.3.4:IpBlock"`. Duplicate detection fails for cross-origin threats — same IP flagged as `IpBlock` and `SuspiciousActivity` are treated as different entries.

**Fix**: Use `make_indicator_key()` consistently. At line 831, change `let key = indicator.indicator_value.clone()` to `let key = make_indicator_key(&indicator.indicator_value, indicator.threat_type)`. Verify all storage and lookup paths use the same key format.

**Verification**: `cargo test --lib -- threat_intel`

---

## Wave 5: High Priority Functional Fixes

**Gate**: After Wave 4 completes. All items in this wave are independent and can be assigned to separate sub-agents in parallel.

#### P1.1: BackendType::Mesh Not Integrated

**Priority**: HIGH
**Files**: `src/router.rs:65,504,748`, `src/http/server.rs`, `src/mesh/proxy.rs`
**Est**: 3-4h

**Problem**: `BackendType::Mesh` is defined in `router.rs:65` and assigned in 9+ places, but the HTTP server handler (`src/http/server.rs`) never dispatches to it. It handles Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, Serverless — but NOT Mesh. The `mesh_backend_pool` field exists but is dead code. Also `is_serverless_origin()` is defined but never called.

**Fix**: In `src/http/server.rs`, add a `BackendType::Mesh` arm to the dispatch match. Wire it to use `mesh_backend_pool` for routing through `MeshProxy::route_request()`. Follow the pattern of the `Upstream` variant but route through mesh instead of direct upstream.

**Verification**: `cargo test --lib -- mesh_proxy && cargo test --test integration_test`

---

#### P1.2: HTTP Client Cache Undersized

**Priority**: HIGH
**File**: `src/http_client/mod.rs` (NOT `src/http/client.rs`)
**Est**: 1h

**Problem**: Default `create_http_client()` at line 162 uses `pool_max_idle_per_host: 100` with `pool_idle_timeout: 30s`. At 500K rps with many upstream backends, 100 idle connections per host is insufficient.

**Fix**: Increase to `pool_max_idle_per_host: 1000` or make it configurable via the HTTP client config. Ensure `pool_idle_timeout` is appropriate.

**Verification**: `cargo test --lib -- http_client`

---

#### P1.3: No Upstream Load Balancing

**Priority**: HIGH
**Files**: `src/http/server.rs`, `src/mesh/proxy.rs`
**Est**: 2-3h

**Problem**: `UpstreamPool` exists in the config/types but is never used for actual load balancing in the request path. All upstream requests go to a single configured backend.

**Fix**: When a site has multiple upstream backends configured, implement round-robin or weighted selection. Wire into the upstream dispatch path in `src/http/server.rs`. Reference `weighted_shuffle_providers()` in `src/mesh/proxy.rs:747-783` for the weighted selection pattern.

**Verification**: `cargo test --lib -- upstream && cargo test --test integration_test`

---

#### P1.4: Message Cache Severely Undersized

**Priority**: HIGH
**File**: `src/mesh/transport.rs:239-244`
**Est**: 2h

**Problem**: `LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 10000)` — 10K capacity at 500K rps gives only a ~1 second dedup window before eviction. Duplicate messages will be processed multiple times under load.

**Fix**: Increase capacity to at least 500K (1M ideal). This trades memory for correctness. At ~100 bytes per cache entry, 500K entries = ~50MB, acceptable for production. Make capacity configurable.

**Verification**: `cargo test --lib -- transport`

---

#### P1.5: Unbounded Proxy Task Spawn

**Priority**: HIGH
**File**: `src/mesh/proxy.rs:962-997`
**Est**: 2h

**Problem**: `for provider in &providers` loop spawns a `tokio::spawn` for each provider with no semaphore or concurrency limit. At 500K rps × 10 providers = 5M concurrent tasks, exhausting system resources.

**Fix**: Add an `Arc<Semaphore>` with configurable max concurrency (e.g., 1000). Wrap each `tokio::spawn` with `semaphore.acquire()`. Alternatively, use a `tokio::sync::JoinSet` with a max tasks limit.

**Verification**: `cargo test --lib -- mesh_proxy`

---

#### P1.6: WASM Instance Pooling Bypass

**Priority**: HIGH
**File**: `src/plugin/wasm_runtime.rs`
**Est**: 2-3h

**Problem**: `filter_request()` (line ~1006) correctly uses pool (`self.pool.get()`). But `transform_response()` (line ~1158) creates a fresh store and calls `self.instantiate()` every time — pooling is bypassed for response transforms.

**Fix**: In `transform_response()`, use `self.pool.get()` to acquire an instance from the pool (same as `filter_request`). Return the instance to the pool after the transform completes.

**Verification**: `cargo test --lib -- wasm_runtime`

---

#### P1.7: Enforce `edge_only` Flag

**Priority**: HIGH
**Files**: `src/mesh/transport.rs:986`, `src/config/site/misc.rs:37`
**Est**: 1h

**Problem**: The `edge_only` config flag exists in site config but is never checked during proxy routing. Non-edge nodes can process requests meant only for edge nodes, and vice versa.

**Fix**: In `MeshProxy::route_request()` (or wherever routing decisions are made), add a check: if the site config has `edge_only = true`, verify that the current node's role `is_edge()`. If not, return an appropriate error or route to an edge node.

**Verification**: `cargo test --lib -- mesh_proxy`

---

#### P1.8: Wire `proxy_cache` in MeshProxy

**Priority**: HIGH
**File**: `src/mesh/proxy.rs:72,333,356,1281-1289`
**Est**: 2h

**Problem**: `proxy_cache: Arc<RwLock<Option<ProxyCache>>>` exists at line 72, initialized at 333, setter at 356, but is NEVER used in `route_request()`. The field is dead weight — no actual response caching occurs. Only `policy_cache` and `transform_cache` are used.

**Fix**: In `route_request()`:
1. Add cache key construction using `CacheKeyBuilder`
2. Before upstream request, check cache: `if let Some(cached) = self.check_proxy_cache(&key) { return cached; }`
3. After successful response, store in cache
4. Use `get_proxy_cache_preferences_for_site()` instead of direct DHT lookup for cache TTL settings

**Verification**: `cargo test --lib -- proxy_cache && cargo test --lib -- mesh_proxy`

---

#### P1.9: WAF SSTI double normalization (SQLi/XSS already fixed)

**Priority**: HIGH
**Files**: `src/waf/attack_detection/ssti.rs:36,55`
**Est**: 30min

**Problem**: SQLi (`sqli.rs:34`) and XSS (`xss.rs:34`) were already fixed to use `normalized.lowercased`. SSTI at `ssti.rs:36` still uses `normalized.normalized` AND then redundantly re-checks raw `input` at line 55. This is double pattern matching.

**Fix**: In `ssti.rs`, use `normalized.lowercased` for pattern matching (matching the SQLi/XSS fix). Remove the redundant raw input re-check at line 55.

**Verification**: `cargo test --lib -- ssti && cargo test --lib -- attack_detection`

---

#### P1.10: Mesh provider_stats Lock Contention

**Priority**: HIGH
**File**: `src/mesh/proxy.rs:69`
**Est**: 1h

**Problem**: `provider_stats: Arc<RwLock<HashMap<String, ProviderStats>>>` uses `parking_lot::RwLock`. Lines 645, 660, 686 all acquire `.write()` on every stats update. At 500K rps this creates massive contention.

**Fix**: Replace `RwLock<HashMap<...>>` with `DashMap<String, ProviderStats>`. Update all read/write access patterns accordingly.

**Verification**: `cargo test --lib -- mesh_proxy`

---

#### P1.11: Sync-on-join YARA/threat intel

**Priority**: HIGH
**File**: `src/mesh/transport_connection.rs:212-253`
**Est**: 2h

**Problem**: `dht_on_peer_connected()` does DHT routing and serverless discovery but has NO YARA or threat intel sync. Both are synced via periodic background tasks only (`threat_intel.rs:1695`, `yara_rules.rs:2039`). New peers start with stale data.

**Fix**: In `dht_on_peer_connected()`, after the DHT routing section, add calls to sync current YARA rules and threat intel state to the newly connected peer. Follow the existing sync message patterns.

**Verification**: `cargo test --lib -- transport_connection`

---

#### P1.12: ServerlessInvokeResponse handling

**Priority**: HIGH
**File**: `src/mesh/transport_peer.rs`
**Est**: 2h

**Problem**: `ServerlessInvokeRequest` is handled (line 2428-2541) but `ServerlessInvokeResponse` has no handler — it appears only in protocol definitions and encode/decode. The invoke result at line 2527-2538 is logged but never sent back to the caller.

**Fix**: Add a handler for `ServerlessInvokeResponse` messages. When a `ServerlessInvokeRequest` completes, construct and send the response back to the requesting node.

**Verification**: `cargo test --lib -- transport_peer`

---

#### P1.13: Add ServerlessInvokeRequest sender

**Priority**: HIGH
**Depends on**: P1.12
**File**: New `src/mesh/transport_serverless.rs`
**Est**: 3h

**Problem**: No code exists to SEND a `ServerlessInvokeRequest` to a peer. The message type is defined in `protocol.rs` but has no sender/invocation path.

**Fix**: Create `src/mesh/transport_serverless.rs` with a function to construct and send signed `ServerlessInvokeRequest` messages. Wire into the serverless invocation path so that when a node needs to invoke a serverless function on a remote origin, it can send the request.

**Verification**: `cargo test --lib -- transport_serverless`

---

#### P1.14: Initialize WasmDistManager

**Priority**: HIGH
**File**: `src/mesh/transport.rs`
**Est**: 1h
**Depends on**: P1.1

**Problem**: `WasmDistManager` exists at `src/mesh/wasm_dist.rs` with global getters/setters but is never initialized during transport setup.

**Fix**: Call `set_global_wasm_dist_manager()` during mesh transport initialization. Provide the appropriate config and signer.

**Verification**: `cargo test --lib -- transport`

---

## Wave 6: Performance Optimizations

**Gate**: Can run in parallel with Wave 5. All items are independent.

#### P2.1: Per-request allocations audit

**Priority**: MEDIUM
**Files**: Multiple hot paths
**Est**: 1-2 weeks (ongoing)

**Problem**: `format!()`, `HashMap::new()`, `to_lowercase()` allocations in hot paths. At 500K rps, each allocation compounds: 1 extra alloc × 500K = 500K allocs/sec.

**Fix**: Systematic audit of hot paths (`src/waf/attack_detection/`, `src/mesh/proxy.rs`, `src/http/server.rs`, `src/http3/server.rs`, `src/proxy/mod.rs`). Replace with thread-local buffers, pre-allocated scratch space, or `Cow<str>`.

---

#### P2.2: Cache key 5 sequential `replace()` calls

**Priority**: MEDIUM
**File**: `src/proxy_cache/key.rs:32-37`
**Est**: 1h

**Problem**: 5 chained `.replace()` calls each allocate a new String.

**Fix**: Use a single-pass replacement or pre-allocate a `String::with_capacity()`. Consider `std::borrow::Cow` to avoid allocation when no replacements needed.

**Verification**: `cargo test --lib -- proxy_cache`

---

#### P2.3: O(n²) weighted_shuffle_providers

**Priority**: MEDIUM
**File**: `src/mesh/proxy.rs:747-783`
**Est**: 15min

**Problem**: Algorithm rebuilds cumulative sum from remaining items and calls `remaining.retain()` each iteration — O(n²).

**Fix**: Use the alias method (Vose's algorithm) for O(n) weighted selection, or use partial sorting.

**Verification**: `cargo test --lib -- mesh_proxy`

---

#### P2.4: serde_json → postcard in hot paths

**Priority**: MEDIUM
**Files**: Multiple (DHT, mesh message serialization)
**Est**: 2-3h

**Problem**: JSON serialization in performance-critical mesh paths.

**Fix**: Replace `serde_json::to_string/from_str` with `crate::serialization::serialize/deserialize` (Postcard) in hot mesh paths. Keep JSON only for admin API responses.

**Verification**: `cargo test --lib -- mesh`

---

#### P2.5: HashMap allocation in entropy calculation

**Priority**: MEDIUM
**File**: `src/waf/attack_detection/mod.rs:410`
**Est**: 30min

**Problem**: `calculate_string_entropy()` allocates a fresh `HashMap<char, usize>` on every call. Runs per-request for every URL.

**Fix**: Use a fixed-size `[usize; 256]` array for character frequency counting instead of HashMap. Much faster and zero allocation.

**Verification**: `cargo test --lib -- attack_detection`

---

#### P2.6: Linear search in open_redirect

**Priority**: MEDIUM
**File**: `src/waf/attack_detection/open_redirect.rs:108-111`
**Est**: 1h

**Problem**: `is_redirect_param()` does `.iter().any(|param| input_lower.contains(param))` — O(n×m) over 80+ patterns.

**Fix**: Pre-compile patterns into a `HashSet<&str>` or Aho-Corasick automaton for O(1) lookup.

**Verification**: `cargo test --lib -- open_redirect`

---

#### P2.7: WASM linker recreation per request

**Priority**: MEDIUM
**File**: `src/plugin/wasm_runtime.rs:500`
**Est**: 1h

**Problem**: `Linker::new(&self.engine)` called in `instantiate()` on every request when pool is empty (and always for `transform_response`).

**Fix**: Cache the `Linker` per module in `WasmRuntime`. Create it once during initialization and clone only the necessary state per instantiation.

**Verification**: `cargo test --lib -- wasm_runtime`

---

#### P2.8: sorted_runtimes() re-sorts every request

**Priority**: MEDIUM
**File**: `src/plugin/wasm_runtime.rs`
**Est**: 30min

**Problem**: `sorted_runtimes()` sorts the runtimes list on every call.

**Fix**: Cache the sorted result. Invalidate only when runtimes are added/removed.

**Verification**: `cargo test --lib -- wasm_runtime`

---

#### P2.9: WASM per-runtime request/env cloning

**Priority**: MEDIUM
**File**: `src/plugin/wasm_runtime.rs`
**Est**: 15min

**Problem**: Clones the `WasmEnv` struct on every request for every runtime.

**Fix**: Use `Arc<WasmEnv>` or a shared reference pattern to avoid cloning.

**Verification**: `cargo test --lib -- wasm_runtime`

---

#### P2.10: HTTP server per-request allocations

**Priority**: MEDIUM
**Files**: `src/http/server.rs`, `src/http3/server.rs`
**Est**: 1h

**Problem**: Various per-request allocations in the HTTP handling path.

**Fix**: Audit and replace with pre-allocated buffers, `Bytes` for zero-copy, or thread-local scratch space.

**Verification**: `cargo test --lib -- http_server`

---

## Wave 7: Code Quality & Cleanup

**Gate**: After Waves 4-6. All items independent.

### 7A: WireGuard Mesh Transport Removal

**Context**: This removes WireGuard **MESH transport** only. The WireGuard **VPN tunnel** in `src/tunnel/wireguard/` and `src/vpn_client/` must be PRESERVED. These are separate concerns.

| Step | File | Action |
|------|------|--------|
| 7A.1 | `src/mesh/wireguard_mesh.rs` | DELETE entire file (246 lines) |
| 7A.2 | `src/mesh/config.rs:257-378` | Remove `WireGuardPerformanceProfile`, `WireGuardPerfConfig`, `MeshWireGuardConfig`, `MeshWireGuardPeer`, and their impl blocks |
| 7A.3 | `src/mesh/config.rs:1471-1492` | Remove `impl MeshWireGuardConfig` methods |
| 7A.4 | `src/mesh/config.rs:227,741,749` | Remove `wireguard_port` fields from `MeshSeedNode`, `MeshNodeEndpoint`, `MeshConfig` |
| 7A.5 | `src/mesh/config_defaults.rs:48` | Change default transport from `WireGuard` to `Quic` |
| 7A.6 | `src/mesh/config.rs:716` | Deprecate (NOT remove) `MeshTransportPreference::WireGuard` variant for config backward compat |
| 7A.7 | `src/mesh/mod.rs:81-82` | Remove `MeshWireGuardConfig`, `MeshWireGuardPeer` from re-exports |
| 7A.8 | `admin-ui/src/types/mod.rs:719` | Remove `wireguard_enabled` from `MeshConfig` type |
| 7A.9 | `admin-ui/src/pages/mesh.rs:49-56` | Remove wireguard toggle from mesh config form |
| 7A.10 | `config/mesh-example.toml:244-281` | Remove WireGuard mesh config section |
| 7A.11 | `AGENTS.md` | Update WireGuard security note |

**DO NOT touch**: `src/tunnel/wireguard/`, `src/vpn_client/`, `src/bin/server.rs:197`, `admin-ui/src/pages/site_editor.rs:1713`, `admin-ui/src/pages/settings.rs:195`

**Verification**: `cargo fmt && cargo clippy -- -D warnings && cargo test --lib --no-run`

---

### 7B: Dead Code Removal

| Step | File:Lines | Item | Action |
|------|-----------|------|--------|
| 7B.1 | `src/mesh/protocol_message.rs:371` | `verify_signature_with_signer` | Remove method |
| 7B.2 | `src/mesh/protocol_message.rs:387` | `verify_signature` | Remove method |
| 7B.3 | `src/platform/ipc.rs:119-148` | `get_default_ipc_path_legacy` | Remove function |
| 7B.4 | `src/waf/flood/connection_limiter.rs:107` | `check_connection` | Remove method |
| 7B.5 | `src/waf/flood/connection_limiter.rs:115` | `register_connection` | Remove method |

**Verification**: `cargo test --lib --no-run` after each removal

---

### 7C: Fix Misleading `#![allow(dead_code)]`

These modules have `#![allow(dead_code)]` but ARE actively used. Remove the attribute after verifying usage via grep:

| File | Used In |
|------|---------|
| `src/waf/flood/syn_flood.rs` | `flood/mod.rs`, `ebpf_flood.rs` |
| `src/challenge/pow.rs` | `challenge/mod.rs:138` |
| `src/overseer/connection_tracker.rs` | Tests, `overseer/mod.rs` |
| `src/overseer/drain_manager.rs` | `overseer/process.rs:99` |
| `src/location_matcher.rs` | `router.rs` (multiple) |

For conditionally-enabled transport modules (correct when mesh feature disabled), keep the attribute:
- `src/mesh/transport_connection.rs`, `transport_dns.rs`, `transport_dht.rs`, `transport_org.rs`, `transport_routing.rs`, `transport_global.rs`, `transport_rate_limit.rs`

---

### 7D: Feature Flag Cleanup

| Step | Action |
|------|--------|
| 7D.1 | Remove `pqc-mesh` from `Cargo.toml:35` (redundant with `post-quantum`; no `#[cfg(feature = "pqc-mesh")]` in codebase) |
| 7D.2 | Audit and remove phantom feature flags: `icmp-winfw`, `icmp-wfp`, `icmp-pf`, `icmp-ebpf` (not in Cargo.toml but referenced) |

**Features to investigate and decide** (not remove immediately):
- `origin_key_exchange`: Incomplete with `unreachable!()` stubs
- `icmp-filter`: 12+ compilation errors
- `tun-rs`: 11+ compilation errors, missing crate dependency

---

### 7E: Other Code Quality Items

#### 7E.1: ConnectionTokenGuard std::Mutex panic risk

**File**: `src/http/server.rs:53,62`
**Est**: 1-2h

**Problem**: `ConnectionTokenGuard` uses `std::sync::Mutex` which panics on poison. In production with panic=abort, this kills the worker process.

**Fix**: Replace with `parking_lot::Mutex` (which does not poison on panic) or handle poison explicitly.

---

#### 7E.2: Admin Regex DoS incomplete protection

**File**: `src/admin/handlers/config.rs:497-509`
**Est**: 2-4h

**Problem**: `check_regex` endpoint calls `check_regex_complexity()` which does static analysis only. It doesn't compile the regex with a timeout, so sophisticated ReDoS patterns that evade heuristics pass through.

**Fix**: Add actual regex compilation with a timeout as a second validation step. If compilation takes > 100ms, reject the regex.

---

#### 7E.3: IPC path traversal

**File**: `src/process/ipc.rs:979-1010`
**Est**: 1-2h

**Problem**: `check_str`/`check_opt_str` validation only checks string length, not path content. No `canonicalize`, `path_clean`, or `..` checking. Fields like `binary_path`, `config_path`, `socket_path` accept traversal characters.

**Fix**: Add path sanitization: reject strings containing `..`, use `Path::canonicalize()` where appropriate, or at minimum validate no path traversal sequences exist.

---

#### 7E.4: Nonce cache O(n) operations

**File**: `src/process/ipc_signed.rs:24-59`
**Est**: 3-4h

**Problem**: `NonceCache` uses `Vec<NonceEntry>` (line 25). `contains()` does linear scan (line 36). `evict_oldest()` does another linear scan (lines 49-57). Both O(n) on every insert.

**Fix**: Replace with `HashSet` for O(1) contains + sorted structure (or `BTreeSet`) for efficient oldest eviction.

---

#### 7E.5: WAF Unicode bypass (%uXXXX IIS-style)

**File**: `src/waf/attack_detection/normalizer.rs`
**Est**: 1-2 days

**Problem**: Normalizer handles `\uXXXX` (backslash-u) and `%XX` percent-encoding, but does NOT handle `%uXXXX` (IIS-style Unicode encoding). No `%u` handling anywhere in normalizer. Attackers can bypass WAF using `%u003C` instead of `%3C` or `<`.

**Fix**: Add `%uXXXX` decoding support to the normalizer. Decode `%uXXXX` sequences to their Unicode codepoint equivalents before pattern matching.

---

#### 7E.6: Header filtering gap in QUIC tunnel path

**File**: `src/mesh/proxy.rs`
**Est**: 2h

**Problem**: Header filtering applied in HTTP path but may be missing in the QUIC tunnel path.

**Fix**: Ensure the same header filtering rules are applied consistently in both HTTP and QUIC/HTTP3 paths.

---

#### 7E.7: Circuit breaker hardcoded values

**File**: `src/mesh/proxy.rs`
**Est**: 2h

**Problem**: Circuit breaker thresholds are hardcoded constants, not configurable.

**Fix**: Make circuit breaker parameters (failure threshold, recovery timeout, etc.) configurable via mesh config.

---

#### 7E.8: Await-holding-lock potential deadlock

**File**: `src/mesh/proxy.rs`
**Est**: 2h

**Problem**: Code holds a lock across `.await` points, which can deadlock under contention.

**Fix**: Restructure to release locks before `.await` points. Use `tokio::task::spawn_blocking` if synchronous lock holding is needed during async operations.

---

#### 7E.9: DNS cache validation unused

**File**: `src/dns/cache.rs:587-596`
**Est**: 8-10h

**Problem**: DNS cache source validation logic exists but is not wired up.

**Fix**: Wire the validation into the cache lookup path, or remove the dead code.

---

## Wave 8: Admin API & DX

**Gate**: After Wave 5. All items independent.

#### P8.1: Rule Feed Sensitive Field Masking

**Priority**: HIGH
**File**: `src/admin/handlers/config.rs:2195-2203`
**Est**: 2h

**Problem**: `GET /config/rule-feed` returns full `public_key` (base64) and `storage_dir` (filesystem path). Exposing the full key helps attackers target signing keys.

**Fix**: Create `RuleFeedConfigReadOnly` response struct:
- `public_key_prefix: Option<String>` (first 4 chars + "...")
- `public_key_configured: bool` (true if key is set and not placeholder)
- Remove `storage_dir` or show only last path component

**Verification**: `cargo test --lib -- admin_handlers`

---

#### P8.2: YARA Feed Sensitive Field Masking

**Priority**: HIGH
**File**: `src/admin/handlers/config.rs:2253-2261`
**Est**: 1h

**Problem**: `GET /config/yara-feed` returns full `signer_public_key`.

**Fix**: Same pattern as P8.1 — create `YaraFeedConfigReadOnly` with `signer_public_key_prefix` and `signer_public_key_configured`.

---

#### P8.3: Overseer Config Bug

**Priority**: HIGH
**File**: `src/startup/master.rs:156-160`
**Est**: 15min

**Problem**: `drain_check_interval_ms` is populated from `main_config.upgrade.drain_check_interval_ms` instead of `main_config.overseer.drain_check_interval_ms`. If a user sets the overseer value, it's silently ignored.

**Fix**: Change the source:
```rust
drain_check_interval_ms: main_config.overseer.drain_check_interval_ms,
```

---

#### P8.4: Swagger UI Integration

**Priority**: LOW
**File**: `src/admin/mod.rs`
**Est**: 1-2h

**Problem**: `utoipa-swagger-ui` is already in Cargo.toml but no route serves it.

**Fix**: Add to router builder:
```rust
.merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", openapi::MaluWafOpenApi::openapi()))
```
Add auth exemption for `/api/docs` and `/api/openapi.json` in middleware (for usability — chicken-and-egg problem accessing docs to learn how to auth).

---

#### P8.5: API Discovery Endpoint

**Priority**: MEDIUM
**File**: New `src/admin/handlers/api_discovery.rs`
**Est**: 4-6h

**Problem**: No `GET /api` endpoint for SDK generators and CLI tools.

**Fix**: Create endpoint returning name, version, openapi_url, docs_url, categories with endpoint counts. Extract from `MaluWafOpenApi::openapi()` paths grouped by tags.

---

#### P8.6: DNS Admin UI Enhancement

**Priority**: MEDIUM
**File**: `admin-ui/src/pages/dns.rs`
**Est**: 4-6h

**Problem**: UI shows ~20% of available DNS fields. Has a field name bug: uses `bind_addresses` but backend returns `bind_address`.

**Fix**:
1. Fix `bind_addresses` → `bind_address`
2. Add missing sections: mode/network, rate limiting, RRL, DNS firewall, settings, mesh DNS, zones, limits, DNSSEC, encrypted DNS (DoT/DoH/DoQ), RPZ, DNS64, prefetch, trust anchors, anycast, recursive
3. Group into collapsible sections matching config structure

---

#### P8.7: Honeypot Port Hot-Reload

**Priority**: MEDIUM
**Files**: New `src/honeypot_port/controller.rs`, `src/worker/unified_server.rs`, `src/admin/handlers/honeypot.rs`
**Est**: 3-4h

**Problem**: Updating `/honeypot/config` writes to `main.toml` but `PortHoneypotRunner` doesn't hot-reload — continues with old config until worker restart.

**Fix**: Create `PortHoneypotController` wrapper around `PortHoneypotRunner` with `update_config()`. Register in `AdminState`. Follow the ICMP handler validate→apply→persist pattern at `src/admin/handlers/icmp.rs:177-230`.

---

#### P8.8: Behavioral Intelligence Admin Endpoint

**Priority**: MEDIUM
**File**: New `src/admin/handlers/behavioral_intel.rs`
**Est**: 2-3h

**Problem**: `BehavioralIntelligenceManager` exists at `src/mesh/behavioral_intel.rs:65` but is not accessible via admin API.

**Fix**: Create endpoints:
- `GET /mesh/behavioral/stats` — fingerprint count, version
- `GET /mesh/behavioral/config` — enabled, thresholds

Note: Manager lives in worker (via `AttackDetector`). May need IPC query or adding to AdminState. Only expose aggregate stats, never raw fingerprints (privacy).

---

## Wave 9: Dependency Updates

**Gate**: Can run in parallel with Waves 5-8.

#### P9.1: yara-x crypto feature reduction

**Priority**: MEDIUM
**File**: `Cargo.toml:117`
**Est**: 30min

**Problem**: yara-x's `crypto` feature pulls `rsa` crate (RUSTSEC-2023-0071 Marvin Attack). We only use pattern matching, not YARA crypto modules.

**Fix**: `yara-x = { version = "1.15", default-features = false, features = ["default-modules"] }`
Note: `rsa` crate is still needed directly for DNSSEC/TLS — only remove the yara-x transitive pull.

---

#### P9.2: sysinfo 0.33 → 0.38

**Priority**: LOW
**Files**: `Cargo.toml`, `src/admin/metrics.rs:29`, `src/admin/state.rs:751-763`
**Est**: 30min

**Fix**: `sysinfo = "0.38"`. Methods used (`System::new_all()`, `cpus()`, etc.) are API-compatible.

---

#### P9.3: bcrypt 0.15 → 0.19

**Priority**: LOW
**Files**: `Cargo.toml`, `src/auth/mod.rs`, `src/auth/basic.rs`, `src/admin/auth.rs`
**Est**: 15min

**Fix**: `bcrypt = "0.19"`. `hash()` and `verify()` APIs unchanged.

---

#### P9.4: wasmtime transitive (monitor)

**Priority**: INFORMATIONAL
**Note**: yara-x pulls wasmtime 40.0.4 (yanked, with CVEs). Direct wasmtime is patched to 42.0.2. No code change needed — monitor yara-x releases for update.

---

## Wave 10: Testing Improvements

**Gate**: Can run in parallel with Waves 7-9.

#### P10.1: WAF core end-to-end tests

Add tests for anomaly scoring, streaming WAF, false positive rates, and attack detection coverage in `src/waf/attack_detection/`.

#### P10.2: Mesh proxy tests

Zero test coverage for `src/mesh/proxy.rs`. Add tests for routing, caching, provider selection, circuit breaker behavior.

#### P10.3: HTTP/3 tests

Add tests for `src/http3/server.rs` — upstream proxying, WAF integration, request handling.

#### P10.4: Overseer lifecycle tests

Test overseer restart, worker drain, health monitoring, config reload.

#### P10.5: Integration test coverage

Expand `tests/integration_test.rs` with mesh routing, serverless invocation, YARA sync scenarios.

#### P10.6: Concurrency stress tests

Add stress tests for DashMap-heavy code paths, concurrent proxy requests, WASM pool contention.

#### P10.7: Hot path benchmarks

Add criterion benchmarks for: attack detection per-request, proxy cache key construction, WASM filter execution, entropy calculation.

---

## Wave 11: New Features

**Gate**: After Waves 5-6 (mesh must be functional first).

#### P11.1: Spin WASM Runtime Support

**Files**: Multiple, ~1300 lines estimated
**Depends on**: P1.1 (mesh integration), P1.6 (WASM pooling)

Implement Spin (Fermyon) WASM runtime support with supervisor pattern. Add admin UI for managing Spin applications. See `src/mesh/wasm_dist.rs` for WASM distribution patterns.

#### P11.2: Serverless Standalone Enhancements

**Files**: Multiple, ~1 week estimated
**Depends on**: P1.12, P1.13

Async compilation, warmup pools, cold-start metrics, async invocation, multi-region support for serverless functions.

---

## Deferred Items

| # | Issue | Reason | Status |
|---|-------|--------|--------|
| D1 | dashmap 5.5.3 → 7.0.0-rc2 | Await stable release; 172 usages, major breaking changes (detached guards) | DEFERRED |
| D2 | notify 6.0.0 → 9.0.0-rc.3 | Major API changes; consider v8.x first | DEFERRED |
| D3 | O(k×n) DHT lookup complexity | Acceptable until 10x/100x scale | DEFERRED |
| D4 | Hardcoded quorum timeout (10s) | Reasonable default for current scale | DEFERRED |
| D5 | Veto abuse score unused | Not currently observed in production | DEFERRED |
| D6 | ArcStr duplication cleanup | `utils.rs` vs `protocol.rs` — cosmetic | DEFERRED |
| D7 | God module splits | metrics/mod.rs (2086 lines), mesh/transport.rs (3291), http/server.rs (4211) | DEFERRED |
| D8 | WASM component support | ABI incompatible with current wasmtime runtime | DEFERRED |
| D9 | Site scope in DHT key | Multi-tenant feature for future release | DEFERRED |
| D10 | IPC key env fallback (`src/process/manager.rs:343-376`) | Intentional opt-in via `allow_insecure_ipc_key` flag | DEFERRED |
| D11 | DNS TSIG timing side channel | ALREADY FIXED — code at `src/dns/tsig.rs:237-244` uses proper constant-time XOR comparison | RESOLVED |

---

## Removed Items (Verified False/Invalid)

| # | Original Claim | Resolution |
|---|----------------|------------|
| ~~P0.10~~ | Rate Limit Bypass via WASM Filters | **REMOVED**: Wrong file references (`unified_server.rs` only 1739 lines). Actual execution order (rate limit → WASM) is correct by design. WASM-blocked requests consuming rate limit quota is intended DDoS protection behavior. Blackhole mode already handles overflow. |
| ~~P0.11~~ | AxumDynamic WAF Bypass | **REMOVED**: False claim. AxumDynamic dispatch in `src/http/server.rs:1702` is inside the `WafDecision::Pass` branch — WAF checks ARE applied. No bypass exists. |

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong for mesh/DHT keys
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary; JSON only for admin API
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`
- **WireGuard**: MESH transport deprecated/non-functional (slated for removal in Wave 7A). VPN tunnel (`src/tunnel/wireguard/`) is separate and working.

---

## Verification Commands

```bash
# Verify tests compile (cargo check does NOT compile test code)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Feature-specific checks
cargo check --features dns
cargo check --features post-quantum
```
