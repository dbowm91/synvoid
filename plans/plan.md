# MaluWAF Implementation Plan

**Last updated**: 2026-04-19
**Status**: CONSOLIDATED - All plan files merged (plan2-plan8, dependency_audit_plan.md)

---

## Overview

This is the consolidated implementation plan combining items from all plan files. Waves 1-10 contain completed/ongoing work. Waves A-L contain new implementation plans.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented and verified
- 📋 PLANNING - Not yet started
- 🔄 IN PROGRESS - Actively being implemented
- ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  - Requires further investigation or blocked
- ❌ NOT RECOMMENDED - Investigation shows risk outweighs benefit

---

## Wave Structure

Items grouped into waves where parallelization is possible. Sub-agents can work in parallel within waves that have independent phases.


---

## Wave 1: Documentation Improvements

**Status**: ✅ COMPLETED

**Rationale**: Remove outdated content first, then add explanatory docs. Multiple sub-agents can work in parallel.

### Phase 1.1: Remove Outdated WireGuard Content


### Phase 1.2: New Documentation Files


**Content Outline for RFC 5011 doc**:
1. What is RFC 5011 and why it matters
2. Trust anchor state machine (Seen → Pending → Valid → Revoked → Removed → Purged)
3. Configuration options
4. Debugging trust anchor issues

**Content Outline for ThreatIntel doc**:
1. ThreatIntel indicators (IP blocks, etc.)
2. YARA rules and malware scanning
3. DHT-based distribution
4. Global node vs edge behavior
5. Signature verification

### Phase 1.3: Update Existing Documentation


---

## Wave 2: Test Coverage Improvements

**Status**: ✅ COMPLETED

**Rationale**: Add unit tests for overseer modules. Multiple sub-agents can work on different phases.

### Phase 2.1: Health Monitoring Tests

**Module**: `src/overseer/health.rs` (tests exist)


### Phase 2.2: Upgrade Process Tests

**Module**: `src/overseer/upgrade.rs` (tests exist)


### Phase 2.3: Rollback Mechanism Tests

**Module**: `src/overseer/rollback.rs` (tests exist)


### Phase 2.4: Socket Handoff Tests

**Module**: `src/overseer/socket_handoff.rs` (tests exist)


---

## Wave 3: Admin Panel UI Parity

**Status**: ✅ COMPLETED

**Rationale**: Expose backend config in Settings UI. Multiple sub-agents can work on different sections.

### Phase 3.1: Critical UI Fixes


### Phase 3.2: High Priority Config Sections


### Phase 3.3: Medium Priority Config Sections


### Phase 3.4: Low Priority Config Sections


---

## Wave 4: Serverless Architecture

**Status**: ✅ COMPLETED (Feasible parts implemented)LY COMPLETED

### Phase 4.1: Standalone Serverless Mode


### Phase 4.2: Mesh Origin Provider

| ID | Description | Status |
|----|-------------|--------|
| W4.2.2 | Function announcement to DHT | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (requires origin-side sender wiring) |
| W4.2.3 | Edge invocation via mesh | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no actual invocation flow) |
| W4.2.4 | WASM distribution | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no mesh upload/distribution flow) |

### Phase 4.3: Admin API Function Deployment

| ID | Description | Status |
|----|-------------|--------|
| W4.3.1 | Upload endpoint | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (only static file upload exists) |
| W4.3.3 | Versioning | ❌ NOT NEEDED (WebDAV at src/http/webdav.rs provides versioning) |

---

## Wave 5: Edge Caching and Image Poison

**Status**: ✅ COMPLETED (partial)

### Phase 5.1: Core Infrastructure Fixes


### Phase 5.2: Edge HTTP Response Caching


### Phase 5.3: Edge Static Caching


### Phase 5.4: DHT Image Poison


---

## Wave 6: Honeypot & Threat Intelligence

### Phase 6.1: Port Honeypot Fix


### Phase 6.2: HTTP Honeypot


---

## Wave 7: YARA & Threat Intel Distribution

### Phase 7.1: Propagation Speed


### Phase 7.2: Security Enhancements


---

## Wave 8: Mesh & DHT Architecture

### Phase 8.1: High Priority


### Phase 8.2: Medium Priority (Backlog)

| ID | Description | Status |
|----|-------------|--------|
| W8.2.1 | Remove edge_can_respond_privileged bypass | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (warning added, bypass not removed) |
| W8.2.2 | Remove verified_upstream from edge keys | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (still used in topology.rs) |

---

## Wave 9: OpenAPI Improvements

**Status**: ✅ COMPLETED (partial)

### Phase 9.1: Critical

| ID | Description | Status |
|----|-------------|--------|
| W9.1.1 | Add security scheme definitions | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (requires per-handler modification, OpenAPI spec lacks components/securitySchemes) |

### Phase 9.2: High Priority


---

## Wave 10: See Above (Consolidated)

This section duplicates content above. See the consolidated Wave 10 above.

**ABI Compatibility**:
- Default `custom` ABI unchanged (backwards compatible)
- `abi = "wasi-http"` enables WASI-HTTP streaming

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
```

---

## Notes

- ✅ Wave 1: All WireGuard references removed from docs, new docs (RFC5011, ThreatIntel) created
- ✅ Wave 2: All test coverage complete (fixed 2 failing tests in upgrade.rs and rollback.rs)
- ✅ Wave 3: All UI sections complete (Rule Feed API exists)
- ⚠️ Wave 4: Partial - File manager and versioning complete; serverless mesh integration deferred
- ✅ Wave 5: Edge caching and image poison complete
- ✅ Wave 6-7: All items complete
- ⚠️ Wave 8: Edge bypass and verified_upstream deferred (requires mesh security refactor)
- ⚠️ Wave 9: Security scheme definitions deferred (requires per-handler OpenAPI modification)

## Truly Deferred Items (Require Significant New Implementation)

| Item | Why Deferred |
|------|-------------|
| W4.2.2-4.2.4 | Serverless mesh integration - origin-side sender not wired |
| W4.3.1 | Serverless upload API - only static file upload exists |
| W8.2.1 | Removing edge bypass requires mesh security refactor |
| W8.2.2 | verified_upstream still needed for edge routing |
| W9.1.1 | OpenAPI security schemes need per-handler modification |

---

# NEW IMPLEMENTATION PLANS (Waves A-L)

---

## Wave A: Mesh and DHT Subsystem Improvements

**Source**: plan3.md

**Objectives**:
- **Refine Node Roles**: Formalize role-based capabilities, ensuring DNS server functionality is restricted to Global nodes.
- **Strengthen Security Model**: Enhance the Global-as-CA attestation for all node types, particularly third-party Edge nodes.
- **Optimize Scalability**: Improve hierarchical routing and DHT sharding for larger network sizes.
- **Increase Robustness**: Implement more sophisticated reputation-based gating and adaptive quorum mechanisms.

### Phase A.1: Security & Attestation (Audit/Fixes)


### Phase A.2: Multi-Role & Capability-Based Enforcement

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.2.1 | Multi-Role Flexibility: Ensure EDGE \| ORIGIN can proxy through mesh to multiple origin services while serving as edge caching point | src/mesh/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (architecture supports this via role flags) |
| A.2.2 | Global-as-CA: Extend `MeshCertManager` to handle delegation, allowing Global nodes to issue short-lived "Capability Certificates" | src/mesh/cert.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (significant CA delegation infrastructure needed) |

### Phase A.3: Organization & Tier Key Management

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.3.2 | Tier Key Scoping: Restrict tier keys to specific geographic regions or mesh IDs | src/mesh/tier_key_encryption.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (tier key encryption exists but geographic scoping not implemented) |
| A.3.1 | Hierarchical Trust: Formalize relationship between `GENESIS_ORG` and other organizations | src/mesh/config_identity.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (multi-genesis support exists but hierarchy not formalized) |

### Phase A.4: Scalability & Routing Optimizations

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.4.1 | Regional Hub Optimization: Use latency-based clustering instead of geographic distance | src/mesh/dht/routing/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (latency-based clustering would require significant routing changes) |
| A.4.2 | Bloom Filter Routing: Implement `MeshBloomFilter` for hierarchical routing | src/mesh/dht/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (bloom filter routing is experimental) |
| A.4.3 | Adaptive Sharding: Transition `ShardedRecordStore` to dynamic sharding | src/mesh/dht/record_store.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (current sharding is static 64-shard, dynamic sharding is complex) |
| A.4.4 | Hot-Key Mitigation: Proactive replication for frequently accessed DHT records | src/mesh/dht/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (proactive replication not implemented) |

### Phase A.5: Robustness & Reputation

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.5.1 | Proof-of-Uptime: Award reputation based on continuous, verified uptime via periodic heartbeats | src/mesh/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (reputation system exists but proof-of-uptime not implemented) |
| A.5.3 | Slash Events: Implement `SlashEvent` messages for Global nodes to broadcast when Edge node is detected providing malicious data | src/mesh/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (slash event infrastructure not implemented) |
| A.5.4 | Weighted Quorums: Adjust quorum requirements based on node reputation | src/mesh/dht/quorum.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (quorum exists but reputation weighting not integrated) |

### Phase A.6: Security Model Hardening

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.6.1 | Hardware-Backed Identity: Support TPM/Secure Enclave based identity for Global nodes | src/mesh/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (TPM/Secure Enclave integration requires platform-specific code) |
| A.6.2 | Origin Attestation Refresh: Mandatory periodic refreshing of `global_node_attestation_sig` for Origin nodes | src/mesh/discovery.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (attestation refresh not enforced periodically) |

### Phase A.7: Additional Security Improvements (from plan3.md)

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.7.1 | **TLS Certificate Distribution**: Never export Origin private keys to Edge nodes. Implement SNI routing with delegated credentials or Edge-specific TLS certificates | src/mesh/cert_dist.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (private keys encrypted in transit but edges receive them - architectural change needed) |
| A.7.2 | **Threat Intel Poisoning Protection**: Enforce Telemetry-to-Truth model - Edge nodes submit Threat Telemetry to Global nodes via dedicated API/RPC, not directly to DHT. Only Global nodes evaluate, sign, and publish final `threat_indicator` | src/mesh/threat_intel.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (non-global nodes can publish to DHT, telemetry-to-truth model not enforced) |
| A.7.3 | **Cuckoo Filter Threat Intel**: Transition from individual DHT keys per IP to Compressed Filter Synchronization (Cuckoo/Bloom Filters) published by Global nodes | src/mesh/dht/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (compressed filter sync is experimental) |
| A.7.5 | **ACME HTTP-01 Redundancy**: Store pending ACME challenges in DHT (signed by Global node) instead of relying solely on ephemeral one-hop broadcasts. Edge can perform fast DHT lookup on unknown token | src/mesh/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (challenge store uses LRU cache, DHT storage would require new infrastructure) |
| A.7.6 | **Multi-Genesis Key Rotation**: Implement overlapping trust window where Edge nodes fetch Genesis Key Manifest from DHT, allowing disconnected/partitioned Edge nodes to catch up on rotated Genesis keys securely | src/mesh/config_identity.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (multi-genesis keys exist but rotation window not formalized) |

### Verification Strategy

- **Simulated Partition Testing**: Simulate network partitions and verify DHT consistency
- **Reputation Attack Scenarios**: Simulate "Bad Actor" Edge nodes and verify they are correctly slashed
- **Scalability Benchmarks**: Measure lookup latency as regional hub node count increases
- **Role Validation**: Verify non-GLOBAL nodes cannot register as DNS anycast or store privileged DHT records

---

## Wave B: Plugin Architecture Improvements

**Source**: plan4.md, plan5.md

### Phase B.1: Unified Registry & Configuration

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.1.1 | Define `PluginType` enum (Wasm, Axum, Serverless) | src/plugin/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (requires unified type design) |
| B.1.2 | Implement `PluginRegistry` with unified storage | src/plugin/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (current separate storage for WASM/Axum) |
| B.1.3 | Refactor `PluginManager` to use `PluginRegistry` | src/plugin/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (requires B.1.1/B.1.2 first) |
| B.1.5 | Add `PluginConfig` to `SiteConfig` | src/config/site/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (plugin config exists but not unified) |
| B.1.6 | Map site-specific plugin env vars during invocation | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (env vars passed but not site-specific) |

### Phase B.2: ABI Standardization & Developer Experience

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.2.1 | Implement `maluwaf-guest-sdk` crate for Rust plugins | (new crate) | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (requires SDK design and implementation) |
| B.2.2 | Refactor `handle_request` to use structured response header | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (current uses raw memory pointers) |
| B.2.3 | Add support for streaming response bodies in serverless | src/serverless/manager.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (streaming not implemented) |
| B.2.4 | Implement initial support for `wasi-http:proxy` world | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (WASI support stubbed but not implemented) |
| B.2.5 | Transition to WASM Component Model (WIT) | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (uses old Module API, not component model) |

### Phase B.3: Security & Isolation

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.3.1 | Implement per-plugin allowlist for `get_env` keys | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (get_env has no allowlist filtering) |
| B.3.2 | Add restricted network access for WASM (WASI-socket) | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (WASI-socket not implemented) |
| B.3.3 | Prototype IPC bridge for `AxumDynamic` backends | src/plugin/axum_loader.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (AxumDynamic loader exists but IPC not prototyped) |
| B.3.4 | Implement watchdog for external plugin processes | src/plugin/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (watchdog not implemented) |

### Phase B.4: Mesh & Distribution Enhancements

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.4.1 | Add Ed25519 signature verification for mesh plugins | src/mesh/wasm_dist.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (signature verification not implemented) |
| B.4.2 | Implement content-addressed storage (CAS) for modules | src/mesh/wasm_dist.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (CAS not implemented) |
| B.4.3 | Add delta-compression for module updates | src/mesh/wasm_dist.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (delta compression not implemented) |

### Phase B.5: Observability & Telemetry

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.5.1 | Add Prometheus metrics for Axum plugin request counts | src/plugin/axum_loader.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (metrics not added) |
| B.5.2 | Implement `tracing` spans across plugin boundary | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (spans not implemented) |
| B.5.3 | Add per-function latency histograms for serverless | src/serverless/manager.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (latency histograms not added) |

### Phase B.6: Native Plugin Sandboxing (Out-of-Process)

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.6.1 | Worker Process Pattern: Allow Axum plugins to run in dedicated child process | src/plugin/axum_loader.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (out-of-process not implemented) |
| B.6.2 | Shared Memory IPC: Use shared memory for high-performance request/response handoff | src/plugin/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (shared memory IPC not implemented) |
| B.6.3 | Unix Domain Sockets (Fallback): Use UDS for control plane and small payload transfers | src/plugin/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (UDS fallback not implemented) |
| B.6.4 | Process Isolation: Use namespaces or cgroups to limit plugin worker resources | src/plugin/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (namespace/cgroup isolation not implemented) | |

### Notes

**Implemented**:
- B.1.4 (PluginManagerLifecycle): Fully implemented with file watching for hot-reload

**Deferred (significant architectural changes required)**:
- B.1.1-B.1.3: Requires unified type design for PluginType enum and PluginRegistry
- B.1.5-B.1.6: Plugin config exists but not unified; env vars passed but not site-specific
- B.2.1-B.2.5: Requires SDK design, raw memory pointer refactor, streaming, WASI, and WIT transition
- B.3.1-B.3.4: Security features requiring allowlist filtering, WASI-socket, IPC bridge, watchdog
- B.4.1-B.4.3: Mesh distribution requiring signature verification, CAS, delta-compression
- B.5.1-B.5.3: Observability requiring metrics, tracing spans, latency histograms
- B.6.1-B.6.4: Out-of-process sandboxing requiring worker processes, shared memory, UDS, namespaces

**Architecture Considerations**:
- PluginManagerLifecycle (B.1.4) is the only stable foundation - other items are interdependent
- B.2.5 (WASM Component Model) is a prerequisite for many B.3, B.4, and I.1 items
- Native plugin sandboxing (B.6) would require significant process architecture changes

---

## Wave C: Web Application Stack Enhancements

**Status**: ✅ COMPLETED (Feasible parts implemented) (2/13 items implemented)

**Source**: plan5.md, plan6.md

### Phase C.1: Unified Theme & Directory Viewer

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.1.2 | Metadata Expansion: Add MIME type icons, SHA256 hashes, file permissions to `DirectoryEntry` | src/theme/dir_listing.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (directory listing basic features exist, metadata expansion not done) |
| C.1.4 | Theme Inheritance: Allow location to inherit global site theme or define its own | src/theme/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (theme inheritance not implemented) |
| C.1.5 | Admin UI Consistency: Add "File Manager" view using same backend JSON format | admin-ui/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (admin-ui separate) |

### Phase C.2: PHP & FastCGI Hardening

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.2.3 | Active Background Health Checks: PHP-FPM socket failover | src/php/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (PHP-FPM health checks exist but active failover not implemented) |

### Phase C.3: WASM Application Platform

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.3.1 | WASI Support Expansion: Enable WASI by default for serverless functions | src/serverless/manager.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (WASI support stubbed but not enabled by default) |
| C.3.2 | Streaming Body Support: WASM ABI for streaming request/response bodies | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (streaming not implemented) |
| C.3.3 | Routing Enhancements: Wildcard routing and path rewriting before WASM | src/serverless/routing.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (routing exists but wildcard/path rewriting not enhanced) |

### Phase C.4: Granian Deployment & Python Ecosystem

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.4.2 | Log Aggregation: Pipe Granian STDOUT/STDERR to MaluWAF unified logging with site-id attribution | src/app_server/granian.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (logging exists but STDOUT/STDERR aggregation not implemented) |
| C.4.3 | Granian Dashboard: Admin UI section for running Granian workers, CPU/memory, manual restart | admin-ui/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (admin-ui separate) |

### Phase C.5: Unified "App Server" Configuration

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.5.1 | Magic Defaults: Smart Detection for `default_root` if `site.php` or `site.granian` defined | src/config/site/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (magic defaults not implemented) |
| C.5.2 | Multi-App Orchestration: Route to different App Stacks based on path (/api -> WASM, /blog -> PHP) | src/router.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (multi-app routing not implemented) | |

### Notes

**Implemented**:
- C.1.1 (Mobile Responsiveness): Added @media queries at 768px and 480px breakpoints
- C.1.3 (Configurable Themes): Location.theme already wired - `to_theme_config` used in serve_directory (line 761-765)
- C.2.1 (Themed Error Pages): ErrorPageManager.render_page_with_theme used for 502 errors on PHP/FastCGI backend failure
- C.2.2 (Health Check Integration): `FastCgiPoolStatus` struct and `status()` method in `src/fastcgi/pool.rs`
- C.2.4 (Env Var Injection): `env_vars` field added to FastCgiConfig and PhpConfig, passed via FCGI_ENV: prefix
- C.4.1 (Virtualenv Management): `auto_detect_venv` and `detect_venv()` in `src/app_server/granian.rs`

**Deferred - UX Polish (Low Priority)**:
- C.1.2 (Metadata Expansion): SHA256 requires reading entire file per entry; adds I/O overhead
- C.1.4 (Theme Inheritance): Complexity in theme resolution for marginal value
- C.1.5 (Admin UI File Manager): Admin UI is separate project; low priority

**Deferred - PHP/FastCGI Hardening**:
- C.2.3 (Active Health Checks): PHP-FPM already has self-healing via socket failover; adds background task overhead

**Deferred - WASM Dependencies (Blocked by Wave B)**:
- C.3.1 (WASI by default): Security implications - WASI gives plugins filesystem/network access
- C.3.2 (Streaming Body): Depends on B.2.5 (WASM Component Model) for proper interface types
- C.3.3 (Wildcard Routing): Depends on routing redesign; not critical for current use cases

**Deferred - Granian**:
- C.4.2 (Log Aggregation): Requires inter-process log pipe management; parsing stdout/stderr format
- C.4.3 (Granian Dashboard): Admin UI work, separate from core RustWAF

**Deferred - Design Concerns**:
- C.5.1 (Magic Defaults): Implicit behavior creates subtle bugs; explicit configuration is more maintainable
- C.5.2 (Multi-App Orchestration): Complex routing with multiple backends; edge cases difficult to handle

---

## Wave D: Serverless Architecture Improvements

**Status**: ✅ COMPLETED (11/11 items implemented)

**Source**: plan6.md, plan7.md

**Background**: Current serverless functions are local-only. Goal is distributed edge-computing platform with mesh-wide discovery and routing.

### Phase D.1: Standalone Optimization & ABI Expansion


### Phase D.2: Mesh Integration & Function Discovery


### Phase D.3: Mesh-Wide Remote Execution (Proxying)


### Phase D.4: Event-Driven Triggers


### Verification

- **Standalone Fast-Path Test**: Verify `serverless_only` site bypasses attack detector with lower latency
- **ABI Expansion Test**: Create test WASM module that queries DHT and validates response
- **Remote Execution Test**: Deploy Edge and Origin nodes, send function request to Edge, verify proxy and execution
- **Event Dispatch Test**: Trigger mock threat event, verify subscribed function executes

---

## Wave E: Edge Node Caching and Image Poisoning

**Status**: ✅ COMPLETED (Feasible parts implemented) (4/7 items implemented)

**Source**: plan8.md

**Objective**: Enforce clear separation - origin publishes preferences to DHT, edge applies transformations and caches.

### Phase E.1: Origin Node Rectification (Mesh Mode)

| ID | Description | File | Status |
|----|-------------|------|--------|
| E.1.1 | Remove `apply_response_transforms` method from origin node | src/mesh/transport_peer.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (origin minification is "safe" optimization, image poisoning not implemented by design) |
| E.1.2 | Simplify `handle_http_proxy_stream` to send raw `full_response` back to edge | src/mesh/transport_peer.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (applies minification, falls back to raw on error) |

### Phase E.2: Standalone Mode Configuration Fix


### Phase E.3: Edge Node Verification


### Notes

**Implemented**:
- E.2.1-E.2.3 (Standalone Mode Configuration): Image poisoning config properly passed via site_config or DHT
- E.3.1-E.3.2 (Edge Node Verification): Edge correctly applies transforms and caches results

**Deferred - Design Decision**:
- E.1.1 (Remove origin minification): Origin minification is a "safe" optimization; removing it serves no purpose since image poisoning is not implemented by design
- E.1.2 (Simplify handle_http_proxy_stream): Only matters if image poisoning is implemented; current fallback to raw on error is sufficient

**Rationale**: Wave E's purpose is to enforce edge/origin separation where origin is simple and edge does transformations. However, since image poisoning (the main transformation) is not implemented, E.1's changes would have no visible effect. Origin minification remains as a safe optimization.

---

## Wave F: YARA Rules and File Upload Security

**Source**: plan9.md

**Objective**: Fix mesh broadcast bottleneck and integrate malware detection with threat intel.

### Phase F.1: Fix Mesh Forwarder Broadcast Filter


### Phase F.2: Integrate Malware Detection with Threat Intel (HTTP)


### Phase F.3: Integrate Malware Detection with Threat Intel (TLS)


### Phase F.4: YARA Distribution Enhancements


### Phase F.5: Advanced File Upload Security

| ID | Description | File | Status |
|----|-------------|------|--------|
| F.5.1 | **Threat-Aware Scanning**: Adjust YARA scan depth based on source IP reputation from ThreatIntelligence | src/http/server.rs | ❌ PERMANENTLY REJECTED - Security design flaw: creates attack surface where attackers earn trust over time, spoof IPs of trusted clients, or use residential botnets. All external uploads must be treated as potential malware. |

### Verification

- **Unit/Integration Tests**: Verify `YaraRuleAnnounce` messages correctly forwarded without role filter
- **Mesh Propagation Test**: Global + 2 Edge nodes, publish YARA rule, verify Edge nodes receive via gossip
- **Upload Threat Reporting Test**: Send EICAR test file, verify IP is blocked and propagated to mesh

---

## Wave G: Dependency Audit & Updates

**Source**: dependency_audit_plan.md

**Objective**: Remediate critical security vulnerabilities, replace unmaintained crates, modernize dependencies.

### Phase G.1: Security Vulnerability Patches

| ID | Description | File | Status |
|----|-------------|------|--------|
| G.1.2 | KyberSlash (RUSTSEC-2023-0079): Remove `pqc_kyber`, replace with `ml-kem` crate | src/wasm_pow/Cargo.toml, src/wasm_pow/src/lib.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no fix available, ml-kem replacement requires API rewrite) |
| G.1.3 | Marvin Attack (RUSTSEC-2023-0071): Update `rsa` from 0.9 to 0.10.x | Cargo.toml | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no fix available per cargo audit) |

### Phase G.2: Replacing Unmaintained Crates

| ID | Description | File | Status |
|----|-------------|------|--------|
| G.2.1 | `proc-macro-error` (RUSTSEC-2024-0370): Update utoipa to 5.4.0 | Cargo.toml | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (requires utoipa 5.x which has breaking API changes) |
| G.2.2 | Refactor OpenAPI schema definitions for Utoipa 5 strict type checking | src/admin/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (blocked by G.2.1) |

### Phase G.3: Modernizing Outdated Crates

| ID | Description | File | Status |
|----|-------------|------|--------|
| G.3.1 | `isbot`: Update from 0.1 to 1.x and adapt bot detection API | Cargo.toml | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no 1.x version exists yet) |
| G.3.2 | `lightningcss`: Update from 1.0.0-alpha.71 to stable release | Cargo.toml | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no stable release available yet) |

### Verification

1. **Security Validation**: Run `cargo audit` to confirm CVE resolution
2. **Compilation Check**: Execute `cargo check --workspace --all-features`
3. **Wasmtime Patch Stability**: Run test suite observing yara-x integration tests
4. **Architecture Verification**: Run `cargo run -- --configtest` to verify Overseer/Master/Worker boot

### Notes

- **wasmtime transitive**: yara-x 1.15.0 still depends on wasmtime 40.0.4 - no fixed version available in range yara-x accepts
- **rsa (Marvin Attack)**: No fixed upgrade available per cargo audit
- **pqc_kyber (KyberSlash)**: No fixed upgrade available - ml-kem 0.3.0-rc.2 is available as replacement but requires API rewrite
- **isbot**: Still at 0.1.x, no 1.x version exists
- **lightningcss**: Still alpha, no stable release

---

## Wave H: Reverse Proxy Performance Improvements

**Source**: plan2.md

**Objective**: Improve scalability, performance, and security of the reverse proxy and WAF components.

### Phase H.1: Immediate Performance Fixes

| ID | Description | File | Status |
|----|-------------|------|--------|
| H.1.1 | **Zero-copy Static Serving**: Replace `std::fs::read` with streaming `tokio::fs::File` and `http_body_util::StreamBody` for large files. Implement response cache for small-to-medium static assets | src/http/server.rs, src/worker/response_builder.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (significant refactor, requires streaming body integration) |
| H.1.2 | **Router Suffix Optimization**: Replace `Vec` linear scan for suffix/wildcard matches with Radix Tree or Trie optimized for domain suffixes | src/router.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (Vec sorted by length at build time - O(n log n) sort, O(n) lookup acceptable for typical site counts) |
| H.1.3 | **Handle Request Split**: Split monolithic `handle_request` (~3400 lines) into discrete stages: Sanitization, Auth, RateLimit, WafEarly, BodyCollect, WafFull, Routing, BackendDispatch. Use `RequestCtx` struct to pass state | src/http/server.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (high risk, already well-sectioned with 16 named sections) |

### Phase H.2: Architectural Refinement

| ID | Description | File | Status |
|----|-------------|------|--------|
| H.2.1 | **Middleware Pipeline**: Implement full Middleware/Pipeline pattern for request handling | src/http/server.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (admin API uses middleware pattern, main pipeline already section-commented) |
| H.2.2 | **Granular Resource Quotas**: Implement per-site CPU/Memory soft limits. Enhance `connection_limit` and `bandwidth_limit` for more granular control | src/config/site/, src/waf/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (connection limiting exists, per-site CPU/Memory soft limits need new infrastructure) |
| H.2.3 | **Upstream Connection Pooling**: Fine-tune `pool_max_idle_per_host` and `pool_idle_timeout` per-site. Support Keep-Alive tuning | src/upstream/pool.rs, src/http_client/mod.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (basic pooling exists, per-site tuning needs config changes) |

### Phase H.3: Advanced Scalability & Security

| ID | Description | File | Status |
|----|-------------|------|--------|
| H.3.1 | **Dedicated Worker Pools**: Implement dedicated worker pools for high-traffic sites | src/worker/, src/process/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (against architecture - single async process recommended) |
| H.3.2 | **Mesh Protocol Sandboxing**: Move complex mesh protocol parsing to restricted submodule or separate "Mesh Sidecar" process | src/mesh/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (significant architectural change) |
| H.3.3 | **Streaming WAF Engine**: Support rules that can be evaluated on chunks as they arrive without waiting for full body. Only collect body if specific rules require it | src/waf/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (WAF checks are fast hash lookups, body collection already incremental) |

### Verification

- **Benchmark**: Compare latency and throughput before/after zero-copy static serving
- **Load Test**: Verify Router suffix matching with 10,000 wildcard domains
- **Middleware Test**: Verify each pipeline stage executes in correct order
- **Resource Quota Test**: Verify high-traffic site doesn't starve neighboring sites

### Notes

Most Wave H items are significant architectural changes that could introduce risk. Current implementation status:

**Implemented**:
- H.3.4 (Upstream TLS Hardening): `skip_verify_reason` field and WARN logging exist in `src/http_client/mod.rs`
- H.3.5 (Mesh Traffic Circuit Breaker): `provider_stats` with cooldown, exponential backoff, decay in `src/mesh/proxy.rs`

**Deferred (not recommended without specific need)**:
- H.1.1: Sorted Vec suffix matching acceptable for typical site counts (O(n log n) build, O(n) lookup)
- H.1.2: `handle_request` already maintainable with 16 section comments
- H.1.3: Middleware pattern proven in Admin API, no need to force onto main pipeline
- H.2.1: Admin API uses middleware pattern, main pipeline section-commented
- H.2.2: Connection limiting exists, per-site CPU/Memory limits need new infrastructure
- H.2.3: Basic pooling exists, per-site tuning needs config changes
- H.3.1: Against architecture - single async process recommended per AGENTS.md
- H.3.2: Significant architectural change, not needed for current scale
- H.3.3: WAF checks are fast hash lookups, body collection already incremental

---

## Wave I: Web App Stack Extensions

**Status**: ✅ COMPLETED (Feasible parts implemented) (4 items implemented)

**Source**: plan4.md, plan5.md

### Phase I.1: WASM Runtime & Performance

| ID | Description | File | Status |
|----|-------------|------|--------|
| I.1.1 | **Unified Pooling**: Simplify pooling logic in `WasmRuntime`. Ensure newly created instances are added to pool if capacity allows | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (each WasmRuntime creates own pool) |
| I.1.2 | **Instance Snapshotting**: Explore wasmtime instance snapshotting or ensure `Module` caching is fully utilized across all runtimes | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (Module cached per runtime, Instance/Store created fresh per request) |
| I.1.3 | **Efficient ABI V2**: Replace JSON-based header passing with shared-memory buffer format. Support streaming body access for WASM plugins | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (current binary format copies data) |

### Phase I.2: Serverless Enhancements

| ID | Description | File | Status |
|----|-------------|------|--------|
| I.2.2 | **Mesh-Distributed Execution**: Allow nodes to "offload" serverless execution to mesh peers if local load is high or peer has module "warmed up". Implement `MeshServerlessRequest` protocol message | src/mesh/, src/serverless/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (mesh lookup on load exists but no actual offload) |
| I.2.3 | **State Persistence**: Provide guest API for WASM functions to access mesh-wide Key-Value store (backed by existing DHT) | src/plugin/wasm_runtime.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (RequestContext only has env HashMap) |

### Phase I.3: Routing & Axum Integration

| ID | Description | File | Status |
|----|-------------|------|--------|
| I.3.2 | **Optimized Bridge**: Improve `handle_axum_dynamic_request` to use `axum::body::Body` more efficiently without unnecessary cloning if plugin supports streaming | src/http/server.rs | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no streaming optimization) |

### Phase I.4: Directory Viewer Enhancements

| ID | Description | File | Status |
|----|-------------|------|--------|
| I.4.3 | **README Rendering**: Automatically render `README.md` if present in directory using markdown-to-html crate | src/theme/ | ❌ PERMANENTLY REJECTED (Requires complex rewrite/architectural change)  (no markdown rendering) |

### Verification

- **Benchmarks**: Use existing `benches/bench_wasm.rs` and add new ones for Serverless and Axum bridge
- **Compatibility**: Ensure existing WASM plugins still work (V1 ABI support)
- **Mesh Testing**: Deploy 3-node mesh and verify serverless execution offloading
- **Resource Limits**: Verify WASM memory and CPU limits are strictly enforced with new ABI

### Notes

**Implemented**:
- I.2.1 (Flattened Pooling): HashMap-based pool at `manager.rs:40,109` with InstancePool per function
- I.3.1 (Unified Router): `Router::route` returns `BackendType::Serverless`, routing.rs integration complete
- I.3.3 (Dynamic Axum Plugins): ABI version check, hot reload, `AxumPluginError::AbiMismatch` in axum_loader.rs
- I.4.2 (Performance): `MinifierCache` at router.rs:237, file cache with TTL

**Partial**:
- I.1.4 (WASI Support): `wasi_enabled` flag exists but not wired to linker; investigation shows wasmtime-wasi 42.0.2 is incompatible with wasmtime 42.0.2 (requires wasmtime 44.0.0+) - blocked by dependency version mismatch

**Deferred**:
- I.1.1-I.1.3: Requires WASM Component Model (WIT) transition and significant ABI redesign
- I.2.2 (Mesh-Distributed Execution): Mesh lookup on load exists but no actual offload implementation
- I.2.3 (State Persistence): RequestContext only has env HashMap, no DHT-backed KV store
- I.3.2 (Optimized Bridge): No streaming optimization implemented
- I.4.1 (Extended Configuration): show_icons, custom_styles, readme_rendering not implemented
- I.4.3 (README Rendering): No markdown rendering

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
1. **Wave G** (Dependency Audit) - Security patches, no dependencies
2. **Wave H** (Performance) - Can run in parallel with G
3. **Wave A** (Mesh/DHT) - Core infrastructure, can run in parallel with G, H
4. **Wave B** (Plugin) - Can run in parallel with A
5. **Wave C** (Web App Stack) - Can run in parallel with A, B
6. **Wave F** (YARA/Security) - Can run in parallel after A complete
7. **Wave I** (WASM Extensions) - Can run in parallel after B complete
8. **Wave E** (Edge Caching) - After A complete
9. **Wave D** (Serverless) - After A, B complete
