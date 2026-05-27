# SynVoid Implementation Plan

Consolidated implementation plan from architecture reviews (2026-05).

## Priority Key
- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Phase 1: Critical Bugs (P0 - Can block other work)

### P0 Items

| ID | Category | Item | Source | Dependencies |
|----|----------|------|--------|--------------|
| **BUG-CORS-1** | Bug | CORS Configuration Ignored in `create_admin_router_with_state` - CORS layer not applied to admin routes | admin_review | None |
| **MR-4** | Security | Implement DhtSyncRequest verification - currently has no auth (security risk) | mesh_review | None |

### Implementation Notes for Phase 1

**BUG-CORS-1** (`src/admin/mod.rs:860`):
- CORS configuration is read with `let _cors_config = cfg.cors.clone();` but the underscore prefix means it's immediately dropped
- The router only has CORS on outer routes via `build_router_from_state()` at line 806
- Nested `/api` routes at lines 179-189 do NOT have CORS applied
- **Fix**: Apply CORS layer in `create_admin_router_with_state()` similar to how it's done in `build_router_from_state()`
- **Verification**: Search for `cors` in `src/admin/mod.rs` to understand the full flow

**MR-4** (`src/mesh/transport_peer.rs:687-704`):
- `DhtSyncRequest` handler validates node_id via `validate_peer_node_id_binding()` but has NO signature verification
- This is a security gap - if TLS transport is compromised, anyone could send DhtSyncRequests
- **Fix**: Add signature verification using `MeshMessageSigner` similar to other DHT messages
- **Reference**: Other messages like `DhtRecordAnnounce` use `verify_for_ingress()` at `signed.rs`

---

## Phase 2: Security & High-Priority Fixes (P1)

### P1 Items

| ID | Category | Item | Source | Dependencies |
|----|----------|------|--------|--------------|
| **DNS-1** | Bug | Wire DNS Cookie Server into Query Validation - exists but not integrated | dns_review | None |
| **L35-1** | Bug | TunnelBackend hardcoded 127.0.0.1 - always routes to localhost | layer_3_5_review | None |
| **WRK-BUG-1** | Bug | HTTP/2 Upstream Hardcoded - `is_http2 = true` at `http_client/mod.rs:893` | worker_review | None |
| **PL-5** | Arch | Consider porting DrainManager to Supervisor for zero-downtime upgrades | process_lifecycle | PL-3 first |
| **WR-1** | DOC | Update WAF connection limit defaults in documentation - actual: Global=1,000, Per-IP=10, Burst=5, Queue=100 | waf_review | None |
| **PLAT-4** | Bug | `is_admin_required_for_tun()` returns true for ALL platforms (stub) | platform_review | None |
| **PLUGIN-2** | Bug | PooledInstance generic trait impl does not reset DHT prefixes or body_receiver | plugin_review | None |

### Implementation Notes for Phase 2

**DNS-1**:
- `DnsCookieServer` exists at `src/dns/cookie.rs:11-50` with `validate_cookie()` at lines 66-87
- Server created at `src/dns/server/mod.rs:850` and passed to `QueryContext`
- **Fix**: In `src/dns/server/query.rs`, call `validate_cookie()` when `cookie_server.is_some()` and query has cookie option
- **Reference**: RFC 8905/RFC 7873 for cookie validation semantics

**L35-1** (`src/tunnel/upstream.rs:121`):
- `Backend::new(format!("tcp:127.0.0.1:{}", self.port))` always routes to localhost
- Note: `TunnelBackend::Direct` variant at `src/tunnel/router.rs:147` accepts dynamic host but is not used
- **Fix**: Use tunnel endpoint configuration instead of hardcoded localhost

**WRK-BUG-1** (`src/http_client/mod.rs:893`):
- `let is_http2 = true;` forces HTTP/2 for all upstream connections
- Infrastructure exists: `enable_http2()`, `http2_only(false)`, `Http2PooledConnection`
- **Fix**: Make `is_http2` configurable via `UpstreamPoolConfig` or similar
- **Impact**: Cannot use HTTP/1.1 for older backends that don't support h2

**PL-5**:
- Overseer has `DrainManager` at `src/overseer/drain_manager.rs` for graceful connection draining
- Supervisor at `src/supervisor/process.rs:1605` only sends SIGTERM without draining
- **Decision needed**: Port DrainManager to Supervisor OR document limitation
- **Dependency**: PL-3 must be resolved first (fate of Overseer)

**WR-1** (WAF defaults documentation fix):
- Current documentation claims: Global=20,000, Per-IP=100, Burst=10, Queue=1,000
- Actual code at `crates/synvoid-config/src/traffic.rs:167-176`:
  - `max_connections: 1000`
  - `max_connections_per_ip: 10`
  - `connection_burst: 5`
  - `connection_queue_size: 100`
- **Fix**: Update `architecture/waf_deep_dive.md` and any other docs

**PLAT-4** (`src/platform/mod.rs:166-171`):
- Stub implementation returns `true` for ALL platforms:
```rust
pub fn is_admin_required_for_tun(&self) -> bool {
    match self {
        Platform::Windows => true,
        _ => true,
    }
}
```
- **Fix**: Implement proper per-platform check or document as incomplete

**PLUGIN-2** (`src/plugin/pool.rs:15-26`):
- Generic `PooledInstance` trait `prepare_for_request()` only resets: `start`, `timeout`, `env`, `fuel`
- Missing resets for: `allowed_dht_prefixes`, `body_receiver`
- Concrete `WasmPooledInstance` at `src/serverless/instance_pool.rs:219` correctly resets all fields
- **Fix**: Add missing resets to trait default impl OR update trait to require these fields

---

## Phase 3: Plugin System Improvements (P1 - Can run parallel to Phase 1-2)

### P1 Items

| ID | Category | Item | Source | Dependencies |
|----|----------|------|--------|--------------|
| **PLUGIN-7** | Arch | `PooledInstance::prepare_for_request` should reset all fields | plugin_review | None |
| **PLUGIN-8** | Arch | Serverless warmup consistency - call `InstancePool::initialize()` from ServerlessManager | plugin_review | None |
| **PLUGIN-9** | Security | Validate Spin manifest exports `handle_request` | plugin_review | None |
| **PLUGIN-10** | Security | Elevate unauthorized DHT query logging to security event level | plugin_review | None |
| **PLUGIN-11** | Security | Make `wasi_enabled: true` configurable per-component | plugin_review | None |

### Implementation Notes for Phase 3

**PLUGIN-7**:
- Same issue as PLUGIN-2 but from architectural perspective
- `prepare_for_request` should accept optional DHT prefixes and body_receiver to match concrete impl

**PLUGIN-8** (`src/serverless/instance_pool.rs:11` vs `src/serverless/mod.rs:96`):
- `ServerlessManager` owns HashMap of functions, pools, routes, config
- `InstancePool::initialize()` pre-warms `pre_warm_instances`
- `ServerlessManager::initialize()` does NOT call `InstancePool::initialize()`
- **Fix**: Add call to `instance_pool.initialize()` in `ServerlessManager::initialize()`

**PLUGIN-9**:
- Spin manifest parsing at `src/spin/manifest.rs` validates TOML but doesn't check for `handle_request` export
- WASM modules without this export will fail at invocation with unclear error
- **Fix**: Add validation that at least one component exports `handle_request`

**PLUGIN-10** (`src/plugin/wasm_runtime.rs:871`):
- Unauthorized DHT queries return `-2` but logging is at `warn` level
- **Fix**: Elevate to `error` or create dedicated security event level for audit trail

**PLUGIN-11** (`src/spin/runtime.rs:196`):
- `wasi_enabled: true` is hardcoded for all Spin components
- **Fix**: Make this configurable per-component in Spin manifest or runtime config

---

## Phase 4: Documentation & Accuracy Fixes (P2)

### P2 Documentation Items

#### Mesh (MR-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **MR-1** | Clarify hierarchical routing is a **reserved/planned** feature, not active | mesh_review | None |
| **MR-2** | Change "Organization Key" to "authorized Organization Public Key" | mesh_review | None |
| **MR-3** | Cross-reference DHT Verification Table - link `signed.rs:42-48` | mesh_review | None |
| **MR-5** | Add `#[allow(dead_code)]` to `hierarchical_routing.rs` or remove | mesh_review | None |
| **MR-7** | Document regional quorum scaling limits | mesh_review | None |

#### Networking (NR-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **NR-1** | Clarify SiteConnectionLimiter is dead code OR implement per-site tracking | networking_review | WR-4 first |
| **NR-2** | Document HTTP/2 connection pooling milestone | networking_review | None |
| **NR-3** | Document protocol detection mechanism at TLS.handshake | networking_review | None |
| **NR-4** | Document QUIC connection migration | networking_review | None |
| **NR-5** | Document 0-RTT security tradeoffs and configuration | networking_review | None |

#### Proxy (PR-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **PR-1** | Update line number references (ErasedHttpClient at 415-456 not 321-370) | proxy_review | None |
| **PR-2** | Document semaphore-based SWR limiting | proxy_review | None |
| **PR-3** | Add test coverage for retry_config flow (BUG-PROXY-1 regression test) | proxy_review | None |
| **PR-4** | Clarify EWMA weight documentation ("90% weight given to historical value") | proxy_review | None |
| **PR-5** | Document PoolKey hashing `(authority, is_http2)` | proxy_review | None |
| **PR-6** | Add ProxyHeadersConfig enhancement tracking ticket | proxy_review | None |

#### WAF (WR-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **WR-2** | Clarify CSS challenge rule syntax: `aspect-ratio: min/max and min/max` format | waf_review | None |
| **WR-3** | Document complete honeypot HTML attributes | waf_review | None |
| **WR-4** | Remove SiteConnectionLimiter or add unit test | waf_review | NR-1 decision |
| **WR-5** | Extract magic numbers into constants with documentation | waf_review | None |
| **WR-6** | Add validation that documented defaults match code defaults | waf_review | None |
| **WR-7** | Add metrics/observability for queue timeout scenarios | waf_review | None |

#### Process Lifecycle (PL-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **PL-1** | Document drain coordination limitation in Supervisor mode (vs Overseer) | process_lifecycle | None |
| **PL-2** | Fix line number references (541 for run_supervisor_mode, 531 for run_master_mode) | process_lifecycle | None |
| **PL-3** | Add Overseer to hierarchy diagram or remove undocumented `run_overseer_mode()` | process_lifecycle | None |
| **PL-4** | Clarify SO_REUSEPORT upgrade path limitations in Supervisor mode | process_lifecycle | None |

#### DNS (DNS-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **DNS-2** | Fix Query Coalescer `max_wait_ms` parameter - currently unused (`_max_wait_ms`) | dns_review | None |
| **DNS-3** | Update DNSSEC documentation - mention ECDSAP256SHA256 (13) and ECDSAP384SHA384 (14) | dns_review | None |
| **DNS-4** | Add NAPTR/CERT/SMMEA/DNAME support to AXFR (currently fall through) | dns_review | None |
| **DNS-5** | Document DNSSEC validation trust chain (RFC 4035 steps) | dns_review | None |

#### Config (CFG-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **CFG-1** | Clarify GranianConfig reference - documentation references non-existent type | config_review | None |
| **CFG-2** | Document `site_filenames` private HashMap field for hot-reload mapping | config_review | None |
| **CFG-3** | Add validation sequence documentation - order validators called in `MainConfig::validate()` | config_review | None |
| **CFG-4** | Document feature interaction (DNS + mesh configs) | config_review | None |
| **CFG-5** | Add examples for hot reload | config_review | None |
| **CFG-6** | Improve ConfigManager load sequence documentation | config_review | None |

#### Routing (RTR-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **RTR-1** | Update line references for `parse_quictunnel_url()` (512-532 not 513-532) | routing_review | None |
| **RTR-2** | Fix PeakEwma reference (520-528 not 48-57) | routing_review | None |
| **RTR-3** | Add metric labels for `max_load_percent` health check threshold | routing_review | None |
| **RTR-4** | Document IP-based routing (`ip_domain_map`, `ip_wildcard_routers`) | routing_review | None |

#### Platform (PLAT-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **PLAT-1** | Update message categories (17 → 18), add Upstream category | platform_review | None |
| **PLAT-2** | Add Supervisor IPC clarification - handles worker messages AND admin commands | platform_review | None |
| **PLAT-3** | Add `supports_seatbelt()` platform capability query for symmetry | platform_review | None |
| **PLAT-5** | Add startup flow enforcement comments to supervisor process | platform_review | None |
| **PLAT-6** | Clarify "Consolidated Mode" vs "Traditional Mode" process architecture | platform_review | None |
| **PLAT-7** | Document `peer_pid()` returns None for Unix IPC streams | platform_review | None |
| **PLAT-8** | Consider explicit IPC transport trait for UnixIpcStream | platform_review | None |
| **PLAT-9** | Document health check interval handles both checks AND zombie reaping | platform_review | None |

#### Worker (WRK-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **WRK-1** | Add health check status to Admin API | worker_review | None |
| **WRK-2** | Document `worker_pool` module purpose vs UnifiedServerWorker | worker_review | None |
| **WRK-3** | Clarify scaling guidance (`tcp.worker_pool_size`, `unified_server_workers`) | worker_review | None |
| **WRK-4** | Document buffer pool implementation location | worker_review | None |
| **WRK-5** | Add sequence diagram for worker startup | worker_review | None |

#### Admin (ADMIN-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **ADMIN-1** | Resolve CORS documentation contradiction (admin_deep_dive.md vs AGENTS.override) | admin_review | None |
| **ADMIN-2** | Update line number references (off by 8-18 lines) | admin_review | None |
| **ADMIN-4** | Clarify 26 vs 27 handlers and feature-gated handlers | admin_review | None |
| **ADMIN-5** | Add session timing normalization to admin_deep_dive.md | admin_review | None |

#### App Handlers (APP-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **APP-2** | Remove WasmiHandler reference - doesn't exist, use ServerlessRoute | app_handlers_review | None |
| **APP-3** | Clarify serverless InstancePool (`src/serverless/instance_pool.rs:11`) | app_handlers_review | None |
| **APP-4** | Add explicit line numbers to handler implementations | app_handlers_review | None |
| **APP-5** | Document BackendType variants mapping to handlers | app_handlers_review | None |
| **APP-6** | Clarify mesh distribution for WASM - verify implementation status | app_handlers_review | None |

#### Plugin (PLUGIN-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **PLUGIN-3** | Update SpinHttpHandler line numbers (dispatch at 2420, creation at 2426) | plugin_review | None |
| **PLUGIN-4** | Document Spin v2 manifest format support | plugin_review | None |
| **PLUGIN-5** | Document async compilation timing (second await error) | plugin_review | None |

#### Layer 3.5 (L35-*)

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **L35-2** | Fix Half-TCP pool key not using authority (documentation accuracy) | layer_3_5_review | None |
| **L35-3** | Clarify HybridSignature vs MeshHybridSigner distinction | layer_3_5_review | None |
| **L35-4** | Document post-quantum feature flag controls X25519MLKEM768 TLS | layer_3_5_review | None |
| **L35-5** | Document Tunnel Backend routing (Direct vs Tunnel) | layer_3_5_review | None |
| **L35-6** | Add ML-KEM timing side-channel consideration (RUSTSEC-2023-0079) | layer_3_5_review | None |
| **L35-7** | Document ACME DNS Challenge integration (dns feature required) | layer_3_5_review | None |
| **L35-8** | Document hybrid signatures performance (2420-byte ML-DSA vs 64-byte Ed25519) | layer_3_5_review | None |
| **L35-9** | Document Raft consensus quorum deadlock risk (MESH-15) | layer_3_5_review | None |
| **L35-10** | Reference rustls-post-quantum dependency in Cargo.toml | layer_3_5_review | None |

#### Config Bugs

| ID | Item | Source | Dependencies |
|----|------|--------|--------------|
| **CFG-BUG-1** | AppServerConfig default port mismatch - `port=Some(8000)`, `host=Some("127.0.0.1")` | config_review | None |

---

## Phase 5: Low-Priority Cleanup (P3)

### P3 Items

| ID | Category | Item | Source |
|----|----------|------|--------|
| **APP-1** | Minifier parameters silently ignored | app_handlers_review |

**APP-1** (`src/static_files/mod.rs:134-138`):
- `new_with_minifier()` accepts `_minifier_cache` and `_async_minifier_client` (underscore = unused)
- Parameters are silently ignored, minification not fully wired
- Per `skills/deferred_items_knowledge.md:44` - known incomplete item

---

## Dependency Ordering

1. **PL-3** (Overseer documentation) should precede **PL-5** (DrainManager porting) - decide fate of Overseer before investing in porting
2. **NR-1** (SiteConnectionLimiter decision) should precede **WR-4** - either document dead code removal OR implement per-site tracking
3. **PL-1** (drain coordination docs) should be done before **PL-5** - document the gap before designing fix
4. **ADMIN-1** (CORS contradiction) should be resolved before **ADMIN-3** (verification) - but note BUG-CORS-1 is the actual bug fix
5. **MR-4 moved to P0** - DhtSyncRequest auth gap is a security issue

---

## Parallelization Waves

### Wave A: Independent Documentation Fixes (Can run in parallel)
All documentation items that have no cross-dependencies:

**WAF Docs** (WR-*):
- WR-1 (WAF defaults), WR-2, WR-3, WR-5, WR-6, WR-7

**Config Docs** (CFG-*):
- CFG-1 through CFG-6, CFG-BUG-1

**Platform Docs** (PLAT-*):
- PLAT-1 through PLAT-9 (except PLAT-4 which is a code fix)

**Proxy/Networking Docs** (PR-*, NR-*):
- PR-1 through PR-6
- NR-1 through NR-5, RTR-1 through RTR-4

**DNS Docs** (DNS-*):
- DNS-2 through DNS-5

**Process Lifecycle Docs** (PL-*):
- PL-1, PL-2, PL-3, PL-4

### Wave B: Module-Specific Code Fixes (Can run in parallel)
Code fixes within a single module:

**Admin API**:
- BUG-CORS-1 (CORS fix)

**Mesh/DHT**:
- MR-4 (DhtSyncRequest auth)

**DNS**:
- DNS-1 (Cookie server wiring)

**Worker/HTTP**:
- WRK-BUG-1 (HTTP/2 configurable)

**Platform**:
- PLAT-4 (stub implementation)

**Tunnel**:
- L35-1 (hardcoded localhost)

### Wave C: Plugin System (Can run in parallel)
All plugin items are independent of Wave A/B:
- PLUGIN-2, PLUGIN-7 (PooledInstance trait fixes)
- PLUGIN-8 (warmup consistency)
- PLUGIN-9, PLUGIN-10, PLUGIN-11 (security hardening)
- PLUGIN-3, PLUGIN-4, PLUGIN-5 (documentation)

### Wave D: Architecture Decisions (May block other work)
- **PL-5** (DrainManager porting) - depends on PL-3 decision
- **MR-6** (MESH-14 - source node ID binding) - deferred per design needed

### Wave E: Mesh Module Documentation (Can run in parallel with other waves)
- MR-1, MR-2, MR-3, MR-5, MR-7

### Wave F: Remaining Documentation (Can run in parallel)
- Worker: WRK-1 through WRK-5
- Layer 3.5: L35-2 through L35-10
- Admin: ADMIN-1, ADMIN-2, ADMIN-4, ADMIN-5
- App: APP-2 through APP-6
- Plugin: PLUGIN-3, PLUGIN-4, PLUGIN-5

---

## Implementation Order Recommendation (for future agents)

1. **Start**: Review AGENTS.md and relevant AGENTS.override.md for module context
2. **Then**: Execute Wave B (P0/P1 code fixes) - these are the highest impact
3. **Then**: Execute Wave A (documentation fixes) - many are independent, can parallelize
4. **Then**: Execute Wave C (Plugin system) - independent of other waves
5. **Then**: Execute Wave E and F (remaining documentation)
6. **Then**: Address Wave D architectural items last

---

## Known Deferred Items (Not in this plan - per AGENTS.md)

| ID | Issue | Reason |
|----|-------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | Requires fundamental changes to bind node_id to TLS/cert identity |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete, requires Raft migration |
| APP-15 | FastCGI Response NOT Truly Streamed | Buffers entire stdout; architectural change needed |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC doesn't need TLS |

---

## Quick Reference: Bugs to Fix

| Bug ID | Severity | Description | Location | Status |
|--------|----------|-------------|----------|--------|
| BUG-CORS-1 | High | CORS Configuration Ignored | `src/admin/mod.rs:860` | **FIXED** |
| MR-4 | High | DhtSyncRequest has no auth | `src/mesh/transport_peer.rs:687-704` | Deferred - breaking proto change |
| DNS-1 | High | DNS Cookie Server not wired | `src/dns/server/query.rs:640-658` | **FIXED 2026-05-27** |
| L35-1 | Medium | TunnelBackend hardcoded 127.0.0.1 | `src/tunnel/upstream.rs:121` | **FIXED** |
| PLUGIN-2 | Medium | PooledInstance DHT/Body leak | `src/plugin/pool.rs:15-31` | **FIXED 2026-05-27** |
| WRK-BUG-1 | Medium | HTTP/2 hardcoded | `src/http_client/mod.rs:893` | **FIXED 2026-05-27** |
| PLAT-4 | Low | Stub always returns true | `src/platform/mod.rs:166-171` | **FIXED** |
| CFG-BUG-1 | Low | AppServerConfig port mismatch | `crates/synvoid-config/src/app_server.rs:49` | Pending |

---

## Fixed Items (For Reference)

The following items were identified in reviews and have been fixed:
- ~~PLUGIN-1~~: Spin Creates New Instance Per Request - **FIXED 2026-05-26**
- ~~PLUGIN-6~~: Spin instance caching by component_id - **FIXED 2026-05-26**
- BUG-L3: ML-KEM key exchange proof-of-possession - **FIXED**
- BUG-ROUTER-1: Hardcoded port 80 - **FIXED**
- use_erased_client hardcoded to false - **FIXED**
- Spin cold-start instance reuse - **FIXED 2026-05-26**
- **BUG-CORS-1**: CORS dead code removed (`src/admin/mod.rs:860` - removed `let _cors_config = cfg.cors.clone();`) - **FIXED 2026-05-27**
- **PLAT-4**: `is_admin_required_for_tun()` stub fixed - now returns `false` for Unix platforms, `true` for Windows - **FIXED 2026-05-27**
- **L35-1**: TunnelBackend now uses configured `upstream_host` from `server_mappings` instead of hardcoded `127.0.0.1` - **FIXED 2026-05-27**
- **DNS-1**: DNS Cookie Server wired into query validation at `src/dns/server/query.rs:640-658` - **FIXED 2026-05-27**
- **PLUGIN-2**: PooledInstance DHT/Body leak fixed - added `allowed_dht_prefixes` field and proper resets in `prepare_for_request()` - **FIXED 2026-05-27**
- **PLUGIN-7**: PooledInstance reset consistency - same fix as PLUGIN-2, unified
- **PLUGIN-8**: Serverless warmup consistency - `InstancePool::initialize()` now called from `ServerlessManager::initialize()` - **FIXED 2026-05-27**
- **PLUGIN-9**: Spin manifest validates HTTP trigger requires URL routes - **FIXED 2026-05-27**
- **PLUGIN-10**: Unauthorized DHT query logging elevated to error level - **FIXED 2026-05-27**
- **WRK-BUG-1**: HTTP/2 now configurable via `is_http2` parameter in `send_request_erased_streaming()` - **FIXED 2026-05-27**
- **MR-4**: DhtSyncRequest auth - Deferred (breaking protobuf protocol change required)
- ~~WRK-BUG-1~~: HTTP/2 configurable - ~~Deferred~~ -> **FIXED 2026-05-27** - Moved to Fixed Items above
- ~~DNS-1~~: DNS Cookie Server wiring - ~~Deferred~~ -> **FIXED 2026-05-27** - Moved to Fixed Items above

---

*Last Updated: 2026-05-27*
