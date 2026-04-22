# MaluWAF Implementation Plan

**Last updated**: 2026-04-22
**Status**: ⚠️ PARTIALLY COMPLETED - Many items remain incomplete

---

## Overview

This is the consolidated implementation plan combining items from all plan files. The plan is organized into waves based on parallelization potential and dependency chains. Sub-agents can work in parallel within waves that have independent phases.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented and verified
- 📋 NOT COMPLETED - Not yet started or incomplete
- 🔄 IN PROGRESS - Actively being implemented
- ❌ PERMANENTLY REJECTED - Requires complex rewrite/architectural change
- ⚠️ ACKNOWLEDGED - Risk accepted with justification

---

## Completed Work (Waves 1-10, A-L)

### Wave 1: Documentation Improvements
**Status**: ✅ COMPLETED

- All WireGuard references removed from docs
- New docs (RFC5011, ThreatIntel) created

### Wave 2: Test Coverage Improvements
**Status**: ✅ COMPLETED

- Inline unit tests exist for overseer modules
- Fixed failing tests in upgrade.rs and rollback.rs

### Wave 3: Admin Panel UI Parity
**Status**: ✅ COMPLETED

- All UI sections complete
- Rule Feed API exists

### Wave 4: Serverless Architecture
**Status**: ✅ COMPLETED (Feasible parts)

- File manager and versioning complete
- Serverless mesh integration deferred

### Wave 5: Edge Caching and Image Poison
**Status**: ✅ COMPLETED (Feasible parts)

- Edge caching and image poison implemented
- Origin minification deferred

### Wave 6: Honeypot & Threat Intelligence
**Status**: ✅ COMPLETED (Feasible parts)

### Wave 7: YARA & Threat Intel Distribution
**Status**: ✅ COMPLETED (Feasible parts)

### Wave 8: Mesh & DHT Architecture
**Status**: ⚠️ PARTIAL

- Edge bypass and verified_upstream deferred (requires mesh security refactor)

### Wave 9: OpenAPI Improvements
**Status**: ✅ COMPLETED (Feasible parts)

- Security scheme definitions deferred (requires per-handler OpenAPI modification)

### Wave 10: Reference Section
**Status**: ✅ COMPLETED

---

## Future Implementation Waves (A-Z)

These waves contain planned future work organized for parallelization.

---

## Wave A: Critical Security Fixes

**Priority**: CRITICAL
**Parallelization**: All phases are independent and can run in parallel
**Status**: ✅ ALL 6 ITEMS COMPLETED (2026-04-22)

### Phase A.1: Honeypot Blocking Fix
✅ IMPLEMENTED - Changed `WafDecision::Stall` to `WafDecision::Block(403, "Forbidden")` in `handle_probe_event()`

**Files**: `src/waf/mod.rs`

---

### Phase A.2: Remove Default Rule Feed Placeholder Key
✅ IMPLEMENTED - Added `PLACEHOLDER_KEY` constant and panic validation in `parse_embedded_key()`

**Files**: `src/waf/rule_feed.rs`

---

### Phase A.3: Fix SSRF Vulnerability in Mesh Proxy
✅ IMPLEMENTED - Added private IP validation before `TcpStream::connect()` in `handle_http_proxy_stream()`

**Files**: `src/mesh/transport_peer.rs`

---

### Phase A.4: Fix X-Forwarded-For Private IP Spoofing
✅ IMPLEMENTED - Reject private IPs in `validate_and_truncate_xff()`

**Files**: `src/proxy/headers.rs`

---

### Phase A.5: Add Location Header Filtering
✅ IMPLEMENTED - Added `"location"` to `HEADERS_TO_STRIP`

**Files**: `src/proxy/headers.rs`

---

### Phase A.6: Fix ThreatIntel Re-announce Bug
✅ IMPLEMENTED - Added `local_origin` check in `re_announce_local_indicators()`

**Files**: `src/mesh/threat_intel.rs`

---

## Wave B: Code Quality - Performance Hot Paths

**Priority**: HIGH
**Parallelization**: Phases are independent
**Status**: ⚠️ 4/10 ITEMS COMPLETED

### Completed Items

**Phase B.1: Pre-compile Regex Patterns in Honeypot Detection**
✅ IMPLEMENTED - Pre-compile patterns using `LazyLock` at module level

**Files**: `src/honeypot_port/threat_intel.rs`

---

**Phase B.3: O(1) Extension Check in File Manager**
✅ IMPLEMENTED - Use `HashSet<String>` with pre-lowercased entries

**Files**: `src/static_files/file_manager.rs`

---

**Phase B.5: Replace `Bytes::new()` with Static Empty**
✅ IMPLEMENTED - Use `Bytes::from_static(&[])` in hot paths

**Files**: `src/http/server.rs`, `src/tls/server.rs`, `src/static_files/mod.rs`

---

**Phase B.6: Fix `method.to_string().as_str()` Pattern**
✅ IMPLEMENTED - Use `method.as_str()` instead

**Files**: `src/http/server.rs`

---

### Not Completed Items

**Phase B.2: Optimize Word Lookup in Probe Tracker**
📋 NOT COMPLETED - `.zip()` still used in word search loop

**Files**: `src/waf/probe_tracker.rs`

---

**Phase B.4: O(1) Domain Matching in Router**
📋 NOT COMPLETED - O(n) Vec iteration still exists

**Files**: `src/router.rs`

---

**Phase B.7: Fix Cache Stampede in `get_or_fetch()`**
📋 NOT COMPLETED - No inflight request tracking

**Files**: `src/proxy_cache/store.rs`

---

**Phase B.8: Eliminate `to_lowercase()` in Hot Loops**
📋 NOT COMPLETED - Many `to_lowercase()` calls remain

**Files**: `src/fastcgi/mod.rs`, `src/theme/dir_listing.rs`, `src/static_files/file_manager.rs`, `src/http/server.rs`

---

**Phase B.9: Fix O(n) Cache Operations**
📋 NOT COMPLETED - `stats()` and `invalidate_by_pattern()` still iterate all entries

**Files**: `src/proxy_cache/store.rs`

---

**Phase B.10: Remove `block_on()` from Sync Functions**
📋 NOT COMPLETED - `block_on()` still used in sync contexts

**Files**: `src/mesh/transport.rs`, `src/mesh/proxy.rs`

---

## Wave C: Web App Stack Improvements

**Priority**: MEDIUM
**Parallelization**: All phases are independent
**Status**: ✅ 3/5 ITEMS COMPLETED

### Completed Items

**Phase C.1: Fix FastCGI Pool Blocking Sleep**
✅ IMPLEMENTED - Converted to async with `tokio::time::sleep()`

**Files**: `src/fastcgi/pool.rs`, `src/fastcgi/mod.rs`

---

**Phase C.2: Fix Granian Blocking I/O in Drop**
✅ IMPLEMENTED - Socket cleanup removed from `Drop`, explicit `cleanup()` method added

**Files**: `src/app_server/granian.rs`

---

**Phase C.3: Improve Granian Health Check**
✅ IMPLEMENTED - Uses `tokio::net::UnixStream::connect()` for socket verification

**Files**: `src/app_server/granian.rs`

---

**Phase C.4: Inject Theme CSS into Custom Directory Templates**
✅ IMPLEMENTED - `render_custom_template` now accepts optional `ThemeConfig`

**Files**: `src/static_files/directory.rs`, `src/static_files/mod.rs`

---

**Phase C.5: Add Admin API for Granian Logs**
✅ IMPLEMENTED - `log_buffer` and endpoint added

**Files**: `src/app_server/granian.rs`, `src/admin/handlers/`

---

## Wave D: YARA & ThreatIntel Distribution

**Priority**: HIGH
**Parallelization**: Phases can run in parallel after Phase D.1
**Status**: ⚠️ 5/6 ITEMS COMPLETED

### Completed Items

**Phase D.1: Add Content Hash Verification in YARA Sync**
✅ IMPLEMENTED - SHA-256 computed and compared against manifest content_hash

**Files**: `src/mesh/yara_rules.rs`

---

**Phase D.2: Add Chunk Signature Verification**
✅ IMPLEMENTED - Chunk signatures verified against manifest's signing public key

**Files**: `src/mesh/yara_rules.rs`

---

**Phase D.4: Make YARA Reload Failures Non-Blocking**
✅ IMPLEMENTED - Log error but continue upload with existing rules

**Files**: `src/static_files/file_manager.rs`

---

**Phase D.5: Add hub_only_mode to YARA Config**
✅ IMPLEMENTED - Added `hub_only_mode` to `YaraRulesMeshConfig`

**Files**: `src/mesh/config.rs`, `src/mesh/yara_rules.rs`

---

### Not Completed Items

**Phase D.3: Wire FileManager HTTP Router**
📋 NOT COMPLETED - `create_file_manager_router()` exists but not registered (requires architectural work)

**Files**: `src/worker/unified_server.rs`, `src/http/file_manager.rs`

---

**Phase D.6: Add Periodic YARA Rule Refresh**
📋 NOT COMPLETED - No background task for periodic refresh

**Files**: `src/static_files/file_manager.rs`

---

## Wave E: Mesh & DHT Architecture

**Priority**: HIGH
**Parallelization**: Independent phases, can run in parallel
**Status**: 📋 0/5 ITEMS COMPLETED

### Not Completed Items

**Phase E.1: Fix Origin Verification**
📋 NOT COMPLETED - `VerifiedUpstream` still stores empty `upstream_url`

**Files**: `src/mesh/dht/mod.rs`, `src/mesh/transport_peer.rs`, `src/mesh/discovery.rs`

---

**Phase E.2: Add Signer Authorization for ThreatIntel**
📋 NOT COMPLETED - Signer's public key not checked against authorized global node list

**Files**: `src/mesh/threat_intel.rs`

---

**Phase E.3: Restrict DNS Server Capability to Global Nodes**
📋 NOT COMPLETED - Edge nodes can announce `dns_server` capability

**Files**: `src/mesh/dht/keys.rs`, `src/mesh/transport.rs`

---

**Phase E.4: Add Per-Peer Replay Cache**
📋 NOT COMPLETED - `ReplayProtection` exists but not instantiated properly

**Files**: `src/mesh/protocol.rs`

---

**Phase E.5: Enforce Minimum Seed Nodes**
📋 NOT COMPLETED - Only warns, doesn't enforce minimum

**Files**: `src/mesh/dht/routing/manager.rs`

---

## Wave F: Serverless Architecture

**Priority**: MEDIUM
**Parallelization**: Phases have dependencies (E.1 before F.3)
**Status**: ⚠️ 5/6 ITEMS COMPLETED

### Completed Items

**Phase F.1: Add ServerlessRouteInfo to Topology**
✅ IMPLEMENTED - `ServerlessRouteInfo` struct exists in topology

**Files**: `src/mesh/topology/types.rs`

---

**Phase F.2: Add invoke_for_mesh Method**
✅ IMPLEMENTED - `ServerlessResponse` and `invoke_for_mesh()` exist

**Files**: `src/serverless/manager.rs`

---

**Phase F.4: Add ServerlessInvokeResponse Protocol Message**
✅ IMPLEMENTED - `ServerlessInvokeResponse` in proto and wire encode/decode

**Files**: `proto/mesh.proto`, `src/mesh/protocol.rs`, `src/mesh/protocol_proto_encode.rs`, `src/mesh/protocol_proto_decode.rs`

---

**Phase F.5: Add Cold Start Metrics**
✅ IMPLEMENTED - Cold start tracking in `InstancePoolMetrics`

**Files**: `src/serverless/instance_pool.rs`

---

**Phase F.6: Implement Graceful Shutdown for Instance Pool**
✅ IMPLEMENTED - `shutdown()` method with timeout and in-flight tracking

**Files**: `src/serverless/instance_pool.rs`

---

### Not Completed Items

**Phase F.3: Modify handle_http_proxy_stream for Serverless**
📋 NOT COMPLETED - No serverless route checking before TCP proxy fallback

**Files**: `src/mesh/transport_peer.rs`

---

## Wave G: Edge Caching & Image Poison

**Priority**: MEDIUM
**Parallelization**: Independent phases
**Status**: ✅ ALL 6 ITEMS COMPLETED

**All items**: G.1-G.6 are implemented

---

## Wave H: Admin Panel Improvements

**Priority**: MEDIUM
**Parallelization**: Independent phases
**Status**: ✅ ALL 6 ITEMS COMPLETED

**All items**: H.1-H.6 are implemented

---

## Wave I: Stub/Incomplete Items

**Priority**: LOW
**Parallelization**: Independent phases
**Status**: ⚠️ 1/3 ITEMS COMPLETED

### Completed Items

**Phase I.3: Document Key Exchange TLS Limitation**
✅ IMPLEMENTED - Log message documents HTTPS proxy requirement

**Files**: `src/mesh/passover_key_exchange.rs`

---

### Not Completed Items

**Phase I.1: Implement HTTP/3 Handler**
📋 NOT COMPLETED - `Http3Handler::handle()` is still a stub

**Files**: `src/http3/handler.rs`

---

**Phase I.2: Implement Threat Intel Local Application**
⚠️ PARTIALLY COMPLETED - `IpThrottle` done, `DomainBlock`, `UrlBlock`, `CertBlock` not integrated

**Files**: `src/mesh/threat_intel.rs`, `src/waf/mod.rs`

---

## Wave J: Dependency & Security Updates

**Priority**: HIGH
**Parallelization**: Independent phases
**Status**: ✅ ALL 3 ITEMS COMPLETED

**All items**: J.1-J.3 are implemented (docs and CI)

---

## Wave K: Documentation Improvements

**Priority**: MEDIUM
**Parallelization**: Independent phases
**Status**: ✅ ALL 4 ITEMS COMPLETED

**All items**: K.1-K.4 are implemented

---

## Wave L: Testing Improvements

**Priority**: MEDIUM
**Parallelization**: Independent phases
**Status**: ✅ ALL 4 ITEMS COMPLETED

**All items**: L.1-L.4 are implemented

---

## Reference Commands

```bash
# Run integration tests
cargo test --test integration_test

# Run DHT integration tests
cargo test --test dht_integration_test

# Run IPC tests
cargo test --test ipc_test

# Run E2E process tests
cargo test --test e2e_process_test

# Verify test compilation
cargo test --lib --no-run

# Run clippy
cargo clippy --lib -- -D warnings

# Format check
cargo fmt --check

# Run all tests
cargo test

# Dependency audit
cargo audit
```

---

## Wave Parallelization Summary

**Recommended Implementation Order**:

1. **Wave A** (Critical Security) - Can run in parallel with Wave J
2. **Wave J** (Dependencies) - Can run in parallel with Wave A
3. **Wave B** (Performance) - Can run in parallel with A, J
4. **Wave D** (YARA/ThreatIntel) - After A, B complete
5. **Wave E** (Mesh/DHT) - After A complete, can parallelize with D
6. **Wave C** (Web App Stack) - Independent, can parallelize with E
7. **Wave F** (Serverless) - After E.1 complete
8. **Wave G** (Edge Caching) - After E complete
9. **Wave H** (Admin UI) - Independent
10. **Wave I** (Stubs) - Low priority
11. **Wave K** (Docs) - Independent
12. **Wave L** (Testing) - Independent

---

## Permanently Rejected Items

These items require complex architectural changes and are permanently rejected:

| Item | Reason |
|------|--------|
| W4.2.2-4.2.4 | Serverless mesh integration - origin-side sender not wired |
| W8.2.1 | Removing edge bypass requires mesh security refactor |
| W9.1.1 | OpenAPI security schemes need per-handler modification |
| A.2.1 | Multi-role flexibility - architecture supports via role flags |
| A.2.2 | Global-as-CA delegation - significant CA infrastructure needed |
| B.1.1-B.6.4 | Plugin unification - requires unified type design |
| H.1.1-H.3.3 | Performance refactors - high risk, current implementation acceptable |

---

## Implementation Progress Summary (2026-04-22)

| Wave | Items | Completed | Status |
|------|-------|-----------|--------|
| A | 6 | 6 | ✅ All completed |
| B | 10 | 4 | ⚠️ 4/10 completed |
| C | 5 | 5 | ✅ All completed |
| D | 6 | 4 | ⚠️ 4/6 completed |
| E | 5 | 0 | 📋 0/5 completed |
| F | 6 | 5 | ⚠️ 5/6 completed |
| G | 6 | 6 | ✅ All completed |
| H | 6 | 6 | ✅ All completed |
| I | 3 | 1 | ⚠️ 1/3 completed |
| J | 3 | 3 | ✅ All completed |
| K | 4 | 4 | ✅ All completed |
| L | 4 | 4 | ✅ All completed |
| **Total** | **64** | **44** | **✅ 44/64 completed** |

### Remaining Items (20 not completed):

**Wave B** (6 items): B.2, B.4, B.7, B.8, B.9, B.10
**Wave D** (2 items): D.3, D.6
**Wave E** (5 items): E.1, E.2, E.3, E.4, E.5
**Wave F** (1 item): F.3
**Wave I** (2 items): I.1, I.2

---

(End of consolidated plan)