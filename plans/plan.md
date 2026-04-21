# MaluWAF Implementation Plan

**Last updated**: 2026-04-21
**Status**: CONSOLIDATED - All plan files merged (plan2-plan21)

---

## Overview

This is the consolidated implementation plan combining items from all plan files. The plan is organized into waves based on parallelization potential and dependency chains. Sub-agents can work in parallel within waves that have independent phases.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented and verified
- 📋 PLANNING - Not yet started
- 🔄 IN PROGRESS - Actively being implemented
- ❌ PERMANENTLY REJECTED - Requires complex rewrite/architectural change
- ⚠️ ACKNOWLEDGED - Risk accepted with justification

---

## Completed Work (Waves 1-10)

These waves have been completed or have feasible parts implemented.

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

### Phase A.1: Honeypot Blocking Fix

**Source**: plan9.md (Task 1.1)

**Issue**: `check_honeypot()` uses `WafDecision::Stall` which delays 30s but still completes, allowing connection exhaustion.

**Recommended Action**: Change to `WafDecision::Block(403, "Forbidden")` for immediate blocking.

**Files**: `src/waf/mod.rs`

---

### Phase A.2: Remove Default Rule Feed Placeholder Key

**Source**: plan9.md (Task 1.2)

**Issue**: If `DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER` not replaced, ALL signature verification fails silently.

**Recommended Action**: Add startup validation that fails hard if placeholder detected.

**Files**: `src/waf/rule_feed.rs`

---

### Phase A.3: Fix SSRF Vulnerability in Mesh Proxy

**Source**: plan10.md (Task 1.1)

**Issue**: `handle_http_proxy_stream()` connects without validating host is not private IP. Default fallback to `127.0.0.1` is dangerous.

**Recommended Action**: Add private IP validation before `TcpStream::connect()`.

**Files**: `src/mesh/transport_peer.rs`

---

### Phase A.4: Fix X-Forwarded-For Private IP Spoofing

**Source**: plan10.md (Task 1.2)

**Issue**: `is_valid_ip()` only checks parseable, not if private IP. Attackers can spoof `X-Forwarded-For: 192.168.1.1`.

**Recommended Action**: Reject private IPs in `validate_and_truncate_xff()`.

**Files**: `src/proxy/headers.rs`

---

### Phase A.5: Add Location Header Filtering

**Source**: plan10.md (Task 1.3)

**Issue**: Response `Location` header can leak internal URLs.

**Recommended Action**: Add `"location"` to `HEADERS_TO_STRIP`.

**Files**: `src/proxy/headers.rs`

---

### Phase A.6: Fix ThreatIntel Re-announce Bug

**Source**: plan16.md (Phase 1.1), plan21.md (Phase 2.1)

**Issue**: `re_announce_local_indicators()` re-publishes ALL indicators including those received from peers. Only local-origin indicators should be re-announced.

**Recommended Action**: Add `local_origin` check in the iteration loop.

**Files**: `src/mesh/threat_intel.rs`

---

## Wave B: Code Quality - Performance Hot Paths

**Priority**: HIGH
**Parallelization**: Phases are independent

### Phase B.1: Pre-compile Regex Patterns in Honeypot Detection

**Source**: plan8.md (Phase 1.1)

**Issue**: 12 regex patterns compiled on every `detect_attack_types()` call.

**Recommended Action**: Pre-compile patterns at module init using `LazyLock`.

**Files**: `src/honeypot_port/threat_intel.rs`

---

### Phase B.2: Optimize Word Lookup in Probe Tracker

**Source**: plan8.md (Phase 1.2)

**Issue**: `.zip()` creates new iterator each call in word search loop.

**Recommended Action**: Use `words_lower` directly without zip.

**Files**: `src/waf/probe_tracker.rs`

---

### Phase B.3: O(1) Extension Check in File Manager

**Source**: plan8.md (Phase 1.3)

**Issue**: O(n) linear scan on every file request.

**Recommended Action**: Use `HashSet<String>` with pre-lowercased entries.

**Files**: `src/static_files/file_manager.rs`

---

### Phase B.4: O(1) Domain Matching in Router

**Source**: plan8.md (Phase 1.4)

**Issue**: O(n) Vec iteration for domain matching.

**Recommended Action**: Use `HashSet` for exact matches, separate structure for suffix matches.

**Files**: `src/router.rs`

---

### Phase B.5: Replace `Bytes::new()` with Static Empty

**Source**: plan17.md (Task 1.1)

**Issue**: `Bytes::new()` allocates on heap for every empty response (~50 locations).

**Recommended Action**: Use `Bytes::static_empty()` in response-building hot paths.

**Files**: `src/http/server.rs`, `src/tls/server.rs`, `src/static_files/mod.rs`

---

### Phase B.6: Fix `method.to_string().as_str()` Pattern

**Source**: plan17.md (Task 1.2)

**Issue**: 4 locations convert HTTP method to String just to borrow as `&str`.

**Recommended Action**: Use `method.as_str()` or add helper function.

**Files**: `src/http/server.rs`

---

### Phase B.7: Fix Cache Stampede in `get_or_fetch()`

**Source**: plan17.md (Task 2.1)

**Issue**: Concurrent cache misses all trigger fetch, causing thundering herd.

**Recommended Action**: Add inflight request tracking with `DashMap<CacheKey, Arc<Mutex<()>>>`.

**Files**: `src/proxy_cache/store.rs`

---

### Phase B.8: Eliminate `to_lowercase()` in Hot Loops

**Source**: plan17.md (Phase 3)

**Files to fix**:
- `src/fastcgi/mod.rs` - header parsing
- `src/theme/dir_listing.rs` - sorting/filtering
- `src/static_files/file_manager.rs` - search
- `src/http/server.rs` - response headers

---

### Phase B.9: Fix O(n) Cache Operations

**Source**: plan17.md (Phase 4)

**Issues**:
- `stats()` iterates all entries - use atomic counters
- `invalidate_by_pattern()` scans ALL entries - add URI index

**Files**: `src/proxy_cache/store.rs`

---

### Phase B.10: Remove `block_on()` from Sync Functions

**Source**: plan8.md (Phase 2.1, 2.2)

**Issue**: `block_on()` in sync functions causes thread starvation in async context.

**Files**: `src/mesh/transport.rs`, `src/mesh/proxy.rs`

---

## Wave C: Web App Stack Improvements

**Priority**: MEDIUM
**Parallelization**: All phases are independent

### Phase C.1: Fix FastCGI Pool Blocking Sleep

**Source**: plan12.md (Wave 1)

**Issue**: `drain_and_reload_pool()` uses `std::thread::sleep()` blocking tokio executor.

**Recommended Action**: Convert to async with `tokio::time::sleep()`.

**Files**: `src/fastcgi/pool.rs`

---

### Phase C.2: Fix Granian Blocking I/O in Drop

**Source**: plan12.md (Phase 2.1)

**Issue**: `std::fs::remove_file()` in `impl Drop` blocks thread.

**Recommended Action**: Remove socket cleanup from `Drop`, add explicit `cleanup()` method.

**Files**: `src/app_server/granian.rs`

---

### Phase C.3: Improve Granian Health Check

**Source**: plan12.md (Phase 2.2)

**Issue**: Health check makes HTTP request rather than verifying socket connectivity.

**Recommended Action**: Use `tokio::net::UnixStream::connect()` for socket verification.

**Files**: `src/app_server/granian.rs`

---

### Phase C.4: Inject Theme CSS into Custom Directory Templates

**Source**: plan12.md (Phase 3.1)

**Issue**: Custom directory templates don't inherit theme CSS.

**Recommended Action**: Modify `render_custom_template` to accept optional `ThemeConfig`.

**Files**: `src/static_files/directory.rs`, `src/static_files/mod.rs`

---

### Phase C.5: Add Admin API for Granian Logs

**Source**: plan12.md (Phase 2.3)

**Issue**: Granian stdout/stderr not queryable via admin API.

**Recommended Action**: Add `log_buffer: RwLock<Vec<String>>` and endpoint `GET /api/system/app-servers/{site_id}/logs`.

**Files**: `src/app_server/granian.rs`, `src/admin/handlers/`

---

## Wave D: YARA & ThreatIntel Distribution

**Priority**: HIGH
**Parallelization**: Phases can run in parallel after Phase D.1

### Phase D.1: Add Content Hash Verification in YARA Sync

**Source**: plan15.md (Phase 1.1), plan11.md (Phase 2.3)

**Issue**: `sync_from_dht()` fetches rule content but never verifies content_hash matches manifest.

**Recommended Action**: After fetching, compute SHA-256 and compare against `manifest.content_hash`.

**Files**: `src/mesh/yara_rules.rs`

---

### Phase D.2: Add Chunk Signature Verification

**Source**: plan15.md (Phase 2.1)

**Issue**: Each chunk has signature but never verified during sync.

**Recommended Action**: Verify chunk signatures against manifest's signing public key.

**Files**: `src/mesh/yara_rules.rs`

---

### Phase D.3: Wire FileManager HTTP Router

**Source**: plan15.md (Phase 3.1)

**Issue**: `create_file_manager_router()` exists but never registered.

**Recommended Action**: Register router in UnifiedServer setup.

**Files**: `src/worker/unified_server.rs`, `src/http/file_manager.rs`

---

### Phase D.4: Make YARA Reload Failures Non-Blocking

**Source**: plan15.md (Phase 4.1)

**Issue**: Upload fails if YARA reload fails during DHT sync.

**Recommended Action**: Log error but continue upload with existing rules.

**Files**: `src/static_files/file_manager.rs`

---

### Phase D.5: Add hub_only_mode to YARA Config

**Source**: plan21.md (Phase 1.1)

**Issue**: No way to restrict YARA DHT publishing to global nodes only.

**Recommended Action**: Add `hub_only_mode` to `YaraRulesMeshConfig`.

**Files**: `src/mesh/config.rs`, `src/mesh/yara_rules.rs`

---

### Phase D.6: Add Periodic YARA Rule Refresh

**Source**: plan15.md (Phase 5.1)

**Issue**: `reload_yara_rules_if_needed()` only triggers during upload.

**Recommended Action**: Add background task with configurable interval (default 60s).

**Files**: `src/static_files/file_manager.rs`

---

## Wave E: Mesh & DHT Architecture

**Priority**: HIGH
**Parallelization**: Independent phases, can run in parallel

### Phase E.1: Fix Origin Verification

**Source**: plan11.md (Wave 1)

**Issues**:
- `VerifiedUpstream` stores empty `upstream_url` with mesh session signature instead of Ed25519 attestation
- Edge node verification expects different data than was signed
- Origin Hello handshake can't obtain attestation

**Recommended Actions**:
1. Modify `VerifiedUpstream` to include actual `upstream_url` and ACME proof
2. Fix signature computation to use Ed25519 attestation
3. Implement attestation request flow in Hello handshake

**Files**: `src/mesh/dht/mod.rs`, `src/mesh/transport_peer.rs`, `src/mesh/discovery.rs`

---

### Phase E.2: Add Signer Authorization for ThreatIntel

**Source**: plan11.md (Phase 2.1)

**Issue**: Signer's public key not checked against authorized global node list.

**Recommended Action**: Add `is_global_node()` check in `sync_from_dht()`.

**Files**: `src/mesh/threat_intel.rs`

---

### Phase E.3: Restrict DNS Server Capability to Global Nodes

**Source**: plan11.md (Phase 3.1)

**Issue**: Edge nodes can announce `dns_server` capability without restriction.

**Recommended Action**: Add access control check in `record_store_crud.rs`.

**Files**: `src/mesh/dht/keys.rs`, `src/mesh/dht/mod.rs`

---

### Phase E.4: Add Per-Peer Replay Cache

**Source**: plan11.md (Phase 4.2)

**Issue**: Global replay cache could allow cross-peer replay attacks.

**Recommended Action**: Track `(peer_id, timestamp, nonce)` tuples.

**Files**: `src/mesh/protocol.rs`

---

### Phase E.5: Enforce Minimum Seed Nodes

**Source**: plan11.md (Phase 4.3)

**Issue**: Only warns, doesn't enforce minimum seed configuration.

**Recommended Action**: Add config option `min_seed_nodes` (default: 3).

**Files**: `src/mesh/dht/routing/manager.rs`

---

## Wave F: Serverless Architecture

**Priority**: MEDIUM
**Parallelization**: Phases have dependencies (E.1 before F.3)

### Phase F.1: Add ServerlessRouteInfo to Topology

**Source**: plan13.md (Task A.1.1)

**Issue**: No `ServerlessRouteInfo` struct for mesh serverless routing.

**Recommended Action**: Add struct with `function_name`, `routes`, `checksum`, etc.

**Files**: `src/mesh/topology/types.rs`

---

### Phase F.2: Add invoke_for_mesh Method

**Source**: plan13.md (Task D.1.1)

**Issue**: No method to invoke serverless functions for mesh callers.

**Recommended Action**: Add `ServerlessResponse` struct and `invoke_for_mesh()` method.

**Files**: `src/serverless/manager.rs`

---

### Phase F.3: Modify handle_http_proxy_stream for Serverless

**Source**: plan13.md (Task C.1.1)

**Issue**: Only performs raw TCP proxying, bypasses serverless dispatch.

**Recommended Action**: Check serverless routes before TCP proxy fallback.

**Files**: `src/mesh/transport_peer.rs`

---

### Phase F.4: Add ServerlessInvokeResponse Protocol Message

**Source**: plan19.md (Phase 1.1)

**Issue**: `ServerlessInvokeRequest` exists but no response type.

**Recommended Action**: Add `ServerlessInvokeResponse` to proto and wire encode/decode.

**Files**: `proto/mesh.proto`, `src/mesh/protocol.rs`, `src/mesh/protocol_proto_encode.rs`, `src/mesh/protocol_proto_decode.rs`

---

### Phase F.5: Add Cold Start Metrics

**Source**: plan13.md (Task B.3.1)

**Recommended Action**: Track cold starts in `InstancePoolMetrics`.

**Files**: `src/serverless/instance_pool.rs`

---

### Phase F.6: Implement Graceful Shutdown for Instance Pool

**Source**: plan13.md (Task B.3.2)

**Recommended Action**: Add `shutdown()` method with timeout and in-flight tracking.

**Files**: `src/serverless/instance_pool.rs`

---

## Wave G: Edge Caching & Image Poison

**Priority**: MEDIUM
**Parallelization**: Independent phases

### Phase G.1: Add ProxyCachePreferences DHT Key

**Source**: plan14.md (Phase 1)

**Issue**: No DHT key for `ProxyCachePreferences`.

**Recommended Action**: Add `UpstreamProxyCachePreferences(String)` variant to `DhtKey`.

**Files**: `src/mesh/dht/keys.rs`

---

### Phase G.2: Publish ProxyCachePreferences to DHT

**Source**: plan14.md (Phase 2)

**Recommended Action**: Call `store_and_announce()` alongside existing transforms.

**Files**: `src/mesh/transport.rs`

---

### Phase G.3: Add Fetch Method for ProxyCachePreferences

**Source**: plan14.md (Phase 3)

**Recommended Action**: Add `get_proxy_cache_preferences_for_site()` method.

**Files**: `src/mesh/transports/manager.rs`

---

### Phase G.4: Apply Preferences in transform_response()

**Source**: plan14.md (Phase 4), plan20.md (Phase 2)

**Recommended Action**: Fetch preferences and call `set_proxy_cache_preferences()`.

**Files**: `src/mesh/proxy.rs`

---

### Phase G.5: Fix Origin Callback Handling

**Source**: plan14.md (Phase 5)

**Issue**: `proxy_cache_preferences` ignored with underscore prefix.

**Recommended Action**: Merge preferences into config JSON before writing.

**Files**: `src/admin/state.rs`

---

### Phase G.6: Add Image Poison to Mesh Proxy Stream

**Source**: plan20.md (Phase 2)

**Issue**: `handle_http_proxy_stream()` doesn't apply image poison.

**Recommended Action**: Fetch image poison config and apply in `apply_response_transforms()`.

**Files**: `src/mesh/transport_peer.rs`

---

## Wave H: Admin Panel Improvements

**Priority**: MEDIUM
**Parallelization**: Independent phases

### Phase H.1: Fix Hardcoded Real-Time Header

**Source**: plan4.md (Section A.1)

**Issue**: `RealtimeHeader` shows static fake values.

**Recommended Action**: Connect to `/api/ws/metrics` WebSocket.

**Files**: `admin-ui/src/components/realtime_header.rs`

---

### Phase H.2: Fix WebSocket Authentication

**Source**: plan4.md (Section A.2)

**Issue**: WebSocket connects without passing Bearer token.

**Recommended Action**: Include token in query parameter.

**Files**: `admin-ui/src/hooks/use_websocket.rs`, `src/admin/ws/mod.rs`

---

### Phase H.3: Add Login / Token Management UI

**Source**: plan4.md (Section A.3)

**Issue**: No UI to obtain or manage auth tokens.

**Recommended Action**: Create login page at `/login`.

**Files**: `admin-ui/src/pages/login.rs`

---

### Phase H.4: Add Traffic Shaping Section

**Source**: plan4.md (Section B.1)

**Recommended Action**: Create `/traffic-shaping` page exposing `TrafficShapingConfig`.

**Files**: `admin-ui/src/pages/traffic_shaping.rs`

---

### Phase H.5: Add HTTP Server Settings

**Source**: plan4.md (Section B.2)

**Recommended Action**: Add HTTP tab to `/settings`.

**Files**: `admin-ui/src/pages/settings.rs`

---

### Phase H.6: Add Security Settings Section

**Source**: plan4.md (Section B.3)

**Recommended Action**: Add Security tab exposing `MainSecurityConfig`.

**Files**: `admin-ui/src/pages/settings.rs`

---

## Wave I: Stub/Incomplete Items

**Priority**: LOW
**Parallelization**: Independent phases

### Phase I.1: Implement HTTP/3 Handler

**Source**: plan2.md (Priority 1)

**Issue**: `Http3Handler::handle()` is placeholder returning OK without processing.

**Recommended Action**: Route HTTP/3 requests through existing pipeline.

**Files**: `src/http3/handler.rs`

---

### Phase I.2: Implement Threat Intel Local Application

**Source**: plan2.md (Priority 2)

**Issue**: `IpThrottle`, `DomainBlock`, `UrlBlock`, `CertBlock` logged but never applied.

**Recommended Action**: Integrate with WAF rate limiting and rule matching.

**Files**: `src/mesh/threat_intel.rs`, `src/waf/mod.rs`

---

### Phase I.3: Document Key Exchange TLS Limitation

**Source**: plan2.md (Priority 3)

**Recommended Action**: Update log message to indicate HTTPS proxy required.

**Files**: `src/mesh/passover_key_exchange.rs`

---

## Wave J: Dependency & Security Updates

**Priority**: HIGH
**Parallelization**: Independent phases

### Phase J.1: Track yara-x wasmtime Vulnerability

**Source**: plan5.md (Task 2.1)

**Current Status**: Direct wasmtime is secure (42.0.2), yara-x bundles vulnerable 40.0.4.

**Recommended Action**: Document in SECURITY.md, monitor for updates.

---

### Phase J.2: Document RSA (Marvin Attack) Exposure

**Source**: plan5.md (Task 2.2)

**Issue**: `rsa` crate unmaintained with no fix available.

**Recommended Action**: Document as acceptable risk (local keys only, not in hot path).

---

### Phase J.3: Add cargo-deny to CI

**Source**: plan5.md (Task 3.1)

**Recommended Action**: Add to CI pipeline for advisory enforcement.

**Files**: `.github/workflows/ci.yml`

---

## Wave K: Documentation Improvements

**Priority**: MEDIUM
**Parallelization**: Independent phases

### Phase K.1: Add Design Rationale to CONFIGURATION.md

**Source**: plan7.md (P1.1)

**Recommended Action**: Explain WHY defaults exist for each configuration group.

---

### Phase K.2: Add Architecture to STATIC_FILES.md

**Source**: plan7.md (P1.2)

**Recommended Action**: Explain minification worker architecture and caching.

---

### Phase K.3: Add IPC/State to PROCESS_MANAGEMENT.md

**Source**: plan7.md (P1.3)

**Recommended Action**: Document IPC session key architecture and state machine.

---

### Phase K.4: Add Calculations to DEPLOYMENT.md

**Source**: plan7.md (P1.4)

**Recommended Action**: Add capacity planning examples with actual calculations.

---

## Wave L: Testing Improvements

**Priority**: MEDIUM
**Parallelization**: Independent phases

### Phase L.1: Expand IPC Message Roundtrip Coverage

**Source**: plan6.md (Phase 1.1)

**Recommended Action**: Add roundtrip tests for ALL `Message` enum variants.

**Files**: `tests/ipc_test.rs`

---

### Phase L.2: Add HMAC Signature Edge Case Tests

**Source**: plan6.md (Phase 1.2)

**Files**: `tests/ipc_test.rs`

---

### Phase L.3: Add Process Lifecycle Integration Tests

**Source**: plan6.md (Phase 3)

**Recommended Action**: Create `tests/process_lifecycle_test.rs`.

---

### Phase L.4: Add Upgrade State Machine Tests

**Source**: plan6.md (Phase 4.1)

**Recommended Action**: Test valid/invalid state transitions.

**Files**: `src/overseer/upgrade.rs`

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

(End of consolidated plan)