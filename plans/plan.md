# SynVoid Implementation Plan

**Status**: ✅ ALL COMPLETED - All waves merged to main (2026-05-23)
**Target**: Bug fixes, security hardening, and documentation updates
**Consolidated from**: All architecture review plans in `plans/` directory

**Completion Summary:**
- Wave 1 (Plugin System Fixes): ✅ COMPLETED - 77e23081
- Wave 2 (WAF Improvements): ✅ COMPLETED - 33a49898
- Wave 3 (Mesh/Networking): ✅ COMPLETED - d04f3962
- Wave 4 (Documentation Fixes): ✅ COMPLETED - e2df1984
- Wave 5 (Config/Admin): ✅ COMPLETED - db15622f
- Wave 6 (Plugin Doc/Enhancements): ✅ COMPLETED - 9ed575ee

All items merged to main branch on 2026-05-23.

---

## Overview

This plan consolidates actionable items from architecture reviews. Each item has been verified against the codebase. Items marked ✅ are verified as already correct/fixed; items marked 📋 need action.

**Key Corrections Made in This Version:**
- SEC-1 (DNS DS digest): ALREADY FIXED - uses `ct_eq()`
- PLUGIN-4 (mesh_check_threat): NOT A BUG - properly implemented with DHT when mesh feature enabled
- M1 (overseer mesh agent): ALREADY FIXED - has `running.is_running()` check at line 412
- H2 (dead code reference): NOT A BUG - function `handle_worker_connection_single` exists at `master/ipc.rs:317-325` (referenced at `supervisor/process.rs:180`)
- SAFE_HEADERS count: 28 headers (not 27 or 29)
- SUP-1 (gRPC no TLS): Working as designed for localhost IPC
- ISSUE-1 (config AGENTS.override.md): ALREADY EXISTS at `src/config/AGENTS.override.md`
- AGENTS.md Spin routing claim: INCORRECT - Spin IS integrated into HTTP dispatch at `src/http/server.rs:2417-2489`

---

## Wave 1: Plugin System Fixes

*Can execute in parallel — no interdependencies*

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| PLUGIN-1 / BUG-1 | Spin `find_route()` returns first match only (no longest-prefix-match) | `src/spin/runtime.rs:271-285` | Implement longest-prefix-match: collect all matching routes, return longest prefix | ✅ DONE |
| BUG-2 | `body_receiver` not reset in `prepare_for_request()` - causes streaming failures on pooled instances | `src/plugin/instance_pool.rs:152-164` | Add `self.store.data_mut().body_receiver = None;` to reset | ✅ DONE |
| BUG-3 | `warmup()` doesn't link all required functions - DHT/env functions unavailable on warm instances | `src/plugin/instance_pool.rs:79-148` | Link all 5 functions: `get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event` | ✅ DONE |
| BUG-4 | Idle eviction timeout hardcoded to 300s, not configurable | `src/spin/runtime.rs:319-338` | Add `idle_timeout_seconds: u64` to `SpinRuntimeConfig`, default 300 | ✅ DONE |

### Implementation Details for Wave 1

**PLUGIN-1 / BUG-1: Spin find_route() fix**
```rust
// Current: returns first match
// Fix: collect all matches, return longest prefix
// In src/spin/runtime.rs:271-285
fn find_route(&self, manifest: &Manifest, path: &str) -> Result<(String, String), SpinRuntimeError> {
    let mut matches = Vec::new();
    for component in &manifest.components {
        if let Some(ref route) = component.url {
            let normalized_route = route.trim_end_matches('/');
            if path == normalized_route || path.starts_with(&format!("{}/", normalized_route)) {
                matches.push((component.id.clone(), route.clone(), normalized_route.len()));
            }
        }
    }
    // Return longest prefix match
    matches.into_iter().max_by_key(|m| m.2)
        .map(|(id, route, _)| (id, route))
        .ok_or_else(|| SpinRuntimeError::RouteNotFound(path.to_string()))
}
```

**BUG-2: body_receiver reset**
```rust
// In src/plugin/instance_pool.rs:152-164
// Add this line in prepare_for_request():
self.store.data_mut().body_receiver = None;  // Reset for streaming
```

**BUG-3: warmup() linker fix**
```rust
// In src/plugin/instance_pool.rs:79-148
// warmup() currently only links: abort, check_timeout
// Need to also link: get_env, synvoid_read_body_chunk, mesh_query_dht, mesh_check_threat, mesh_emit_event
// See full linker setup in instance_pool.rs around lines 95-140
```

---

## Wave 2: WAF Improvements

*Can execute in parallel with Wave 1*

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| REC-2 | Flood protector NOT integrated into request pipeline (exists at TCP level only) | `src/waf/mod.rs:438-508` | Integrate flood protector into `check_request_full()` pipeline | ✅ DONE |
| REC-3 | Streaming WAF `get_block_status` always returns 403 for all attack types | `src/waf/attack_detection/streaming.rs:356-365` | Make block status configurable per attack type | ✅ DONE |
| REC-5 | Request smuggling NOT included in fast-path checks - security bypass vulnerability | `src/waf/attack_detection/mod.rs:425-435` | Add smuggling indicators to fast_path_patterns OR remove early return | ✅ DONE |
| REC-1 | Fast-path pre-screening patterns incomplete (13 patterns, missing most SQLi, command injection, SSRF, XXE, etc.) | `src/waf/attack_detection/mod.rs:156-171` | Expand fast_path_patterns to include critical patterns from each category | ✅ DONE |
| REC-4 | Behavioral analysis mesh-only limitation undocumented | `src/waf/attack_detection/mod.rs:263-314` | Document that behavioral analysis requires `mesh` feature | ✅ DONE |

### WAF Bugs to Fix

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| BUG-5 | Double UTF-8 lossy conversion in body handling | `src/waf/attack_detection/mod.rs:890-892` | Investigate and fix double conversion | ⚠️ No issue found |
| REC-6 | FloodBackend Display missing Ebpf variant | `src/waf/flood/mod.rs:66-72` | Add Ebpf variant to Display impl | ✅ DONE |
| REC-7 | `block_scrapers` hardcoded to true, ignores parameter | `src/waf/bot.rs:91` | Make configurable via parameter | ✅ DONE |

### Implementation Details for Wave 2

**REC-2: Flood protector integration**
```rust
// In src/waf/mod.rs:438-508 (check_request_full)
// Add after TCP connection check:
if let Some(ref protector) = self.flood_protector {
    match protector.check_tcp_connection(ip) {
        FloodDecision::RateLimited => return WafDecision::Block(429, "Rate Limited"),
        FloodDecision::Blackholed => return WafDecision::Drop,
        FloodDecision::Allowed => {}
    }
}
```

**REC-1: Fast-path pattern expansion**
```rust
// Current patterns at src/waf/attack_detection/mod.rs:156-171
// Add: command separators (; | & $()), SQL keywords (UNION SELECT DROP),
// encoding (%00 %2f), template injection ({{, ${)
```

---

## Wave 3: Mesh/Networking

*Can execute in parallel with Wave 1/2*

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| N1 | Hierarchical routing dead code - `#[allow(dead_code)]` since file is unused | `src/mesh/hierarchical_routing.rs` | Implement or remove - decide based on multi-region roadmap | ✅ DONE - Documented as reserved for multi-region |
| N4 | Test assertion message claims bug that appears to be fixed | `src/mesh/dht/signed.rs:1803-1806` | Update assertion message to reflect current behavior | ✅ DONE |
| N5 | Missing integration test for Regional Quorum | `src/mesh/dht/quorum.rs` | Add test: 50-node cluster, latency-based selection, fallback behavior | ✅ DONE - Test already exists |

### Mesh Low Priority

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| N6 | Add more descriptive metrics | `src/mesh/dht/quorum.rs`, `src/mesh/dht/record_store_message.rs` | Metrics: regional vs full quorum, verification failures, Raft write failure rates | ✅ DONE |
| N7 | Document PQC feature flag | `src/mesh/config.rs`, `architecture/networking_deep_dive.md` | Document ML-KEM/ML-DSA via `post-quantum` feature flag | ✅ DONE |

---

## Wave 4: Documentation Fixes

*Can execute in parallel with other waves*

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| H1 | Update architecture docs to reflect three-tier hierarchy (Overseer→Master→Worker) | `architecture/process_lifecycle.md`, `architecture/platform_deep_dive.md` | Documentation claims 2-tier but code has 3-tier | ✅ DONE |
| H3 | Update `process_lifecycle.md` to remove non-existent `src/control_plane/` reference | `architecture/process_lifecycle.md:16` | Module `src/control_plane/` does not exist | ✅ DONE |
| M2 | Expand startup flow documentation in `platform_deep_dive.md` to match actual complexity | `architecture/platform_deep_dive.md:201-217` | Actual flow has 15+ phases vs documented 11 steps | ✅ DONE |
| M3 | Add Overseer row to process hierarchy table | `architecture/platform_deep_dive.md:113-121` | Missing Overseer in hierarchy table | ✅ DONE |
| N3 | Update `mesh_deep_dive.md` accuracy | `architecture/mesh_deep_dive.md` | 1) Hierarchical routing "reserved for future" not "uses" 2) Audit system not centralized 3) Collective defense features "partial/experimental" | ✅ DONE |
| C1 | Update `deep_dive_review.md:15` - Remove "protected by TLS" from gRPC description | `architecture/deep_dive_review.md:15` | gRPC has no TLS, intentional for localhost IPC | ✅ DONE |
| C2 | Update `architecture/overview.md:202` - Clarify Spin support status | `architecture/overview.md:202`, `src/http/server.rs:2417-2489` | Spin routing IS integrated at HTTP dispatch level; requires manual app registration via Admin API | ✅ DONE |
| C3 | Clarify Master process status in `architecture/overview.md` | `architecture/overview.md:56-58`, `src/main.rs:529-537` | `--master` flag still exists; Master not fully deprecated | ✅ DONE |
| C4 | Create centralized errata section in `architecture/overview.md` | `architecture/overview.md` | Reference AGENTS.md for known path corrections | ✅ DONE |

### Documentation Fix Details

**H1: Three-tier hierarchy update**
The actual architecture in legacy mode is:
```
Overseer (src/overseer/)
├── Master (src/startup/master.rs:205-797)
│   ├── Admin API
│   ├── BlockStore
│   └── Workers (spawned via IPC)
└── Supervisor (new consolidated mode, replaces Overseer+Master)
```

**C2: Spin routing clarification**
- Spin IS integrated into HTTP dispatch at `src/http/server.rs:2417-2489`
- When `BackendType::Spin` is configured, requests are routed to `SpinHttpHandler`
- Spin apps must be pre-registered via Admin API (`/spin/apps` endpoint)
- Route matching uses prefix-only comparison - no regex, glob, or priority ordering

---

## Wave 5: Config/Admin

*Can execute in parallel*

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| ISSUE-1 | `src/config/AGENTS.override.md` already exists | N/A | ✅ Already created | ✅ DONE |
| DOC-1 | TunnelMessage types incomplete (missing AuthFailure, KeepAlive, PortData, etc.) | `src/tunnel/quic/messages.rs:7-106` | Update `dns_deep_dive.md` | ✅ DONE |
| DOC-2 | WireGuard implementation wrong - uses `defguard-boringtun`, not `wireguard-kit` | `src/tunnel/wireguard/userspace.rs:136` | Fix documentation | ✅ DONE |
| DOC-3 | VPN client `VpnClientBuilder` is method on VpnClient, not separate struct | `src/vpn_client/mod.rs:65-76` | Update documentation | ✅ DONE |
| DOC-4 | Missing undocumented DNS modules (hsm.rs, cookie.rs, update.rs, transfer.rs, etc.) | Various | Add to key files table | ✅ DONE - Table already accurate |
| DOC-5 | DNSSEC manual wire format limitation not documented | `src/dns/dnssec.rs:1-9` | Add note about limitation | ✅ DONE |

### Config/Admin Low Priority (Optional)

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| ISSUE-3 | `SESSION_COOKIE_NAME` defined in two places | `src/admin/handlers/auth.rs:12`, `src/admin/middleware.rs:54` | Consolidate constant | ✅ DONE |
| ISSUE-4 | YARA rate limiter cleanup task not auto-started | `src/admin/state.rs:86-143` | Ensure task auto-starts on admin state creation | ✅ DONE |
| ISSUE-5 | Handler count is 28, should be 29 (missing `behavioral_intel`) | `architecture/admin_deep_dive.md:120` | Update handler count | ✅ DONE |

---

## Wave 6: Plugin Documentation/Enhancements

*Can execute in parallel*

| ID | Issue | File:Line | Action | Status |
|----|-------|-----------|--------|--------|
| PLUGIN-2 | No `load_plugin_from_memory_with_priority` method | `src/plugin/wasm_runtime.rs:162-177` | Add for mesh plugin distribution | ✅ DONE |
| PLUGIN-3 | Mesh-only features not documented | `src/serverless/manager.rs:145-171` | Add feature-gate documentation for serverless mesh integration | ✅ DONE |
| PLUGIN-5 | `load_component()` is stub - loads but never uses | `src/plugin/wasm_runtime.rs:184-210` | Either implement fully or remove dead code | ✅ DONE - Removed dead code |
| PLUGIN-6 | Missing `memory_budget_mb` field in documentation | `architecture/plugin_deep_dive.md:33` | Update documentation | ✅ DONE |

### Plugin Enhancement Details

**PLUGIN-3: Mesh-only features in serverless**
When `mesh` feature is enabled, these methods are available:
- `ServerlessManager::set_record_store()` - registers functions in DHT
- `ServerlessManager::set_routing_manager()` - enables hierarchical routing
- `ServerlessManager::verify_caller_permission()` - DHT-based permission verification

---

## Deferred Items (Architectural/Large Effort)

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | DHT ingress validation gaps require fundamental changes to bind node_id to TLS/cert identity | Deferred - Architectural |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214`. Requires Raft migration. | Deferred - Requires Raft |
| MESH-17 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state for bidirectional communication | Working As Designed |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout. True streaming requires architectural refactor. | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC between Supervisor and Master processes | Working As Designed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Requires documenting full identity/trust model - larger architectural task | Deferred |

---

## Already Verified As Correct

| Item | Source | Verification |
|------|--------|--------------|
| SEC-1 (DNS DS digest) | `src/dns/dnssec_validation.rs:273` | Uses `ct_eq()` - FIXED |
| PLUGIN-4 (mesh_check_threat) | `src/plugin/wasm_runtime.rs:946-960` | Properly implemented with DHT integration - NOT A BUG |
| M1 (overseer mesh agent spawn) | `src/overseer/process.rs:412` | Has `running.is_running()` check - FIXED |
| H2 (dead code reference) | `src/supervisor/process.rs:180` | Function exists at `master/ipc.rs:317` - NOT A BUG |
| SAFE_HEADERS count | `src/proxy/cache.rs:97-126` | 28 headers (not 27 or 29) |
| MESH-11 (Quorum Manager race) | `src/mesh/dht/quorum.rs:337-381` | FIXED - uses oneshot with Result tracking |
| MESH-16 (Role validation duplication) | `src/mesh/peer_auth.rs:275-304` | FIXED - duplicate block removed |
| APP-17 (pip install hashes) | `src/app_server/granian.rs:491-508` | FIXED - require_hashes field added |
| ISSUE-1 (config AGENTS.override.md) | `src/config/AGENTS.override.md` | File exists and is complete |

---

## Verification Commands

```bash
# Check Spin find_route implementation
grep -n "fn find_route" src/spin/runtime.rs

# Check Plugin instance pool prepare_for_request
grep -n "body_receiver" src/plugin/instance_pool.rs

# Check WAF fast-path patterns
grep -n "fast_path_patterns" src/waf/attack_detection/mod.rs

# Check flood protector integration
grep -n "flood_protector" src/waf/mod.rs

# Check hierarchical routing
grep -n "allow(dead_code)" src/mesh/hierarchical_routing.rs

# Core profile check
cargo check --no-default-features

# Mesh profile check
cargo check --no-default-features --features mesh

# Full profile check
cargo check --no-default-features --features mesh,dns

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Run all lib tests (compile check)
cargo test --lib --no-run
```

---

## Summary

| Wave | Items | Focus | Status |
|------|-------|-------|--------|
| 1 | 4 | Plugin System Fixes | ✅ DONE |
| 2 | 8 | WAF Improvements | ✅ DONE |
| 3 | 5 | Mesh/Networking | ✅ DONE |
| 4 | 9 | Documentation Fixes | ✅ DONE |
| 5 | 8 | Config/Admin | ✅ DONE |
| 6 | 4 | Plugin Doc/Enhancements | ✅ DONE |
| **Total** | **37** | **Action items** | ✅ ALL COMPLETE |

| Category | Count |
|----------|-------|
| High Priority | 5 (BUG-1, BUG-2, BUG-3, REC-2, REC-5) |
| Medium Priority | 19 |
| Low Priority | 13 |
| Deferred | 6 |
| Already Fixed/Done | 10 |
| Completed | 31 |

---

## Implementation Order Recommendation

### Phase 1 (Parallel - Independent)
- **Wave 1**: Plugin fixes (BUG-1, BUG-2, BUG-3, BUG-4) - 4 items
- **Wave 6**: Plugin documentation (PLUGIN-2, PLUGIN-3, PLUGIN-5, PLUGIN-6) - 4 items

### Phase 2 (Parallel - After Phase 1)
- **Wave 2**: WAF improvements - 8 items (includes REC-4 documentation fix)
- **Wave 3**: Mesh/Networking - 5 items

### Phase 3 (Documentation - Can run parallel)
- **Wave 4**: Documentation fixes - 9 items

### Phase 4 (Lower priority)
- **Wave 5**: Config/Admin - 8 items (ISSUE-1 is DONE)

---

## Detailed Implementation Notes

### AGENTS.md Correction Needed

The line in AGENTS.md that states "Spin framework partially implemented... routing integration and component mapping is NOT implemented" is **incorrect**. Spin IS integrated into HTTP dispatch at `src/http/server.rs:2417-2489`. Update AGENTS.md line 175 to reflect this.

### Spin find_route() Longest Prefix Match Implementation

Current behavior in `src/spin/runtime.rs:271-285`:
- Iterates through components
- Returns first matching route (prefix or exact)
- No HTTP method filtering
- No priority ordering

Required fix:
- Collect all matching routes
- Return the one with longest prefix match
- Consider adding method matching and explicit priority field

### WAF Fast-Path Bypass Concern

The `is_fast_path_safe()` function at `src/waf/attack_detection/mod.rs:425-435` returns early when fast-path is safe, but request smuggling patterns are NOT in the 13 fast_path_patterns. This means:
1. Smuggling attacks bypass fast-path and go directly to heavy detectors
2. Smuggling detectors run in parallel via JoinSet but with lower priority score
3. Consider adding smuggling indicators to fast_path_patterns

---

**Last Updated**: 2026-05-23
**Verification Status**: ✅ All items verified against codebase. 37 action items, 6 deferred, 10 already correct/working as designed.