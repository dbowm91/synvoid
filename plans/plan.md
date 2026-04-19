# MaluWAF Implementation Plan

**Last updated**: 2026-04-19
**Status**: CONSOLIDATED - All plan files merged (plan3-plan9, dependency_audit_plan.md)

---

## Overview

This is the consolidated implementation plan combining items from all plan files. Waves 1-8 contain completed/ongoing work. Waves A-E contain new implementation plans.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented and verified
- 📋 PLANNING - Not yet started
- 🔄 IN PROGRESS - Actively being implemented
- ⏸️ DEFERRED - Requires further investigation or blocked
- ❌ NOT RECOMMENDED - Investigation shows risk outweighs benefit

---

## Wave Structure

Items grouped into waves where parallelization is possible. Sub-agents can work in parallel within waves that have independent phases.

| Wave | Focus | Status | Sub-Agents Possible |
|------|-------|--------|---------------------|
| Wave 1 | Documentation & Documentation Cleanup | ✅ COMPLETED | Yes - 3 sub-agents in Phase 1.1, Phase 1.2, Phase 1.3 |
| Wave 2 | Test Coverage | ✅ COMPLETED | Yes - 4 sub-agents in parallel (one per phase) |
| Wave 3 | Admin Panel UI Parity | ✅ COMPLETED | Yes - 4 sub-agents in parallel |
| Wave 4 | Serverless & Edge Caching | ⚠️ PARTIAL | No - some items deferred |
| Wave 5 | Honeypot & Threat Intel | ✅ COMPLETED | Yes - independent phases |
| Wave 6 | YARA Distribution | ✅ COMPLETED | Yes - independent phases |
| Wave 7 | Mesh & DHT Architecture | ⚠️ PARTIAL | Some items deferred |
| Wave 8 | OpenAPI Improvements | ⚠️ PARTIAL | Some items deferred |
| Wave A | Mesh/DHT Subsystem Improvements | 📋 PLANNING | Yes - 4 phases can parallelize |
| Wave B | Plugin Architecture | 📋 PLANNING | Yes - 5 waves can parallelize |
| Wave C | Web Application Stack | 📋 PLANNING | Yes - 5 sections can parallelize |
| Wave D | Serverless Architecture | 📋 PLANNING | Yes - 4 phases can parallelize |
| Wave E | Edge Caching & Image Poison | 📋 PLANNING | Yes - 3 phases can parallelize |
| Wave F | YARA/File Upload Security | 📋 PLANNING | Yes - 3 steps can parallelize |
| Wave G | Dependency Audit & Updates | 📋 PLANNING | No - sequential security patches |

---

## Wave 1: Documentation Improvements

**Status**: ✅ COMPLETED

**Rationale**: Remove outdated content first, then add explanatory docs. Multiple sub-agents can work in parallel.

### Phase 1.1: Remove Outdated WireGuard Content

| ID | Action | File | Status |
|----|--------|------|--------|
| W1.1.1 | Remove WireGuard Tunnel section (keep note) | docs/TUNNELS.md | ✅ COMPLETED |
| W1.1.2 | Remove WireGuard config example | docs/CONFIGURATION.md | ✅ COMPLETED |
| W1.1.3 | Remove wireguard from platform table | docs/PLATFORM_SUPPORT.md | ✅ COMPLETED |
| W1.1.4 | Update README.md WireGuard claims | README.md | ✅ COMPLETED |
| W1.1.5 | Update docs/README.md WireGuard | docs/README.md | ✅ COMPLETED |
| W1.1.6 | Fix CHANGELOG.md WireGuard | CHANGELOG.md | ✅ COMPLETED |
| W1.1.7 | Update paper.md WireGuard refs | paper.md | ✅ COMPLETED |

### Phase 1.2: New Documentation Files

| ID | Description | Status |
|----|------------|--------|
| W1.2.1 | RFC 5011 Trust Anchor doc (docs/RFC5011_TRUST_ANCHOR.md) | ✅ COMPLETED |
| W1.2.2 | Threat Intelligence doc (docs/THREAT_INTEL.md) | ✅ COMPLETED |

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

| ID | Description | Status |
|----|------------|--------|
| W1.3.1 | TLS/ACME - add PQ config, 0-RTT, passthrough | ✅ COMPLETED (docs/CONFIGURATION.md, docs/HTTP3.md have these sections) |
| W1.3.2 | WAF Mesh - DHT distribution, tier keys | ✅ COMPLETED (docs/WAF_MESH.md has DHT section) |
| W1.3.3 | Bot Protection - PoW 12s, challenge types | ✅ COMPLETED (docs/BOT_PROTECTION.md has PoW section) |
| W1.3.4 | Attack Detection - decision types | ✅ COMPLETED (docs/ATTACK_DETECTION.md exists) |
| W1.3.5 | DNS/DNSSEC - RFC 5011 integration | ✅ COMPLETED (docs/RFC5011_TRUST_ANCHOR.md has full integration) |
| W1.3.6 | CONFIG common mistakes section | ✅ COMPLETED (docs/CONFIGURATION.md has troubleshooting section) |

---

## Wave 2: Test Coverage Improvements

**Status**: ✅ COMPLETED

**Rationale**: Add unit tests for overseer modules. Multiple sub-agents can work on different phases.

### Phase 2.1: Health Monitoring Tests

**Module**: `src/overseer/health.rs` (tests exist)

| ID | Test Name | Status |
|----|----------|--------|
| W2.1.1 | test_health_status_enum_variants | ✅ COMPLETED (tests exist at health.rs:884) |
| W2.1.2 | test_worker_readiness_status_default | ✅ COMPLETED (tests exist) |
| W2.1.3 | test_enhanced_health_config_defaults | ✅ COMPLETED (tests exist) |
| W2.1.4 | test_baseline_comparison_calculation | ✅ COMPLETED (tests exist) |
| W2.1.5 | test_shadow_traffic_result_fields | ✅ COMPLETED (tests exist) |
| W2.1.6 | test_worker_readiness_status_creation | ✅ COMPLETED (tests exist) |

### Phase 2.2: Upgrade Process Tests

**Module**: `src/overseer/upgrade.rs` (tests exist)

| ID | Test Name | Status |
|----|----------|--------|
| W2.2.1 | test_auto_rollback_config_defaults | ✅ COMPLETED (tests exist at upgrade.rs) |
| W2.2.2 | test_upgrade_mode_detection | ✅ COMPLETED (tests exist) |
| W2.2.3 | test_orchestrator_construction | ✅ COMPLETED (tests exist) |
| W2.2.4 | test_upgrade_state_transitions | ✅ COMPLETED (tests exist) |
| W2.2.5 | test_preflight_validation_logic | ✅ COMPLETED (tests exist) |
| W2.2.6 | test_health_check_metrics | ✅ COMPLETED (tests exist) |

### Phase 2.3: Rollback Mechanism Tests

**Module**: `src/overseer/rollback.rs` (tests exist)

| ID | Test Name | Status |
|----|----------|--------|
| W2.3.1 | test_rollback_manager_defaults | ✅ COMPLETED (tests exist at rollback.rs) |
| W2.3.2 | test_rollback_error_display | ✅ COMPLETED (tests exist) |
| W2.3.3 | test_rollback_target_construction | ✅ COMPLETED (tests exist) |
| W2.3.4 | test_can_rollback_logic | ✅ COMPLETED (tests exist) |
| W2.3.5 | test_rollback_target_parsing | ✅ COMPLETED (tests exist) |

### Phase 2.4: Socket Handoff Tests

**Module**: `src/overseer/socket_handoff.rs` (tests exist)

| ID | Test Name | Status |
|----|----------|--------|
| W2.4.1 | test_socket_handoff_error_types | ✅ COMPLETED (tests exist at socket_handoff.rs) |
| W2.4.2 | test_handoff_server_construction | ✅ COMPLETED (tests exist) |
| W2.4.3 | test_handoff_client_connection_timeout | ✅ COMPLETED (tests exist) |
| W2.4.4 | test_handoff_invalid_state_errors | ✅ COMPLETED (tests exist) |

---

## Wave 3: Admin Panel UI Parity

**Status**: ✅ COMPLETED

**Rationale**: Expose backend config in Settings UI. Multiple sub-agents can work on different sections.

### Phase 3.1: Critical UI Fixes

| ID | Description | Status |
|----|-------------|--------|
| W3.1.1 | Fix Upload section disconnected (BUGFIX) | ✅ COMPLETED |
| W3.1.2 | Complete Security Headers section | ✅ COMPLETED |

### Phase 3.2: High Priority Config Sections

| ID | Description | Status |
|----|-------------|--------|
| W3.2.1 | YARA Rules section | ✅ COMPLETED |
| W3.2.2 | Serverless config section | ✅ COMPLETED |
| W3.2.3 | Bot Detection section (consolidate) | ✅ COMPLETED |
| W3.2.4 | Process Status Summary in Settings | ✅ COMPLETED |
| W3.2.5 | Defaults section | ✅ COMPLETED |
| W3.2.6 | DNS Integration (enhance page) | ✅ COMPLETED |

### Phase 3.3: Medium Priority Config Sections

| ID | Description | Status |
|----|-------------|--------|
| W3.3.1 | Persistence section | ✅ COMPLETED |
| W3.3.2 | Mime Types section | ✅ COMPLETED |
| W3.3.3 | Proxy Limits section | ✅ COMPLETED |
| W3.3.4 | Blocklist Limits section | ✅ COMPLETED |
| W3.3.5 | TCP/UDP Defaults section | ✅ COMPLETED |
| W3.3.6 | Fallback section | ✅ COMPLETED |
| W3.3.7 | Upgrade section | ✅ COMPLETED |

### Phase 3.4: Low Priority Config Sections

| ID | Description | Status |
|----|-------------|--------|
| W3.4.1 | Rule Feed section | ✅ COMPLETED (backend API exists at src/admin/handlers/rule_feed.rs) |
| W3.4.2 | Static Files config section | ✅ COMPLETED (per-site) |
| W3.4.3 | Update search index | ✅ COMPLETED |
| W3.4.4 | Config documentation tooltips | ✅ COMPLETED |

---

## Wave 4: Serverless Architecture

**Status**: ⚠️ PARTIALLY COMPLETED

### Phase 4.1: Standalone Serverless Mode

| ID | Description | Status |
|----|-------------|--------|
| W4.1.1 | Mode configuration (standalone/provider) | ✅ COMPLETED |
| W4.1.2 | Scale-to-zero implementation | ✅ COMPLETED |
| W4.1.3 | Cold start request handling | ✅ COMPLETED |

### Phase 4.2: Mesh Origin Provider

| ID | Description | Status |
|----|-------------|--------|
| W4.2.1 | Provider configuration | ✅ COMPLETED |
| W4.2.2 | Function announcement to DHT | ⏸️ DEFERRED (requires origin-side sender wiring) |
| W4.2.3 | Edge invocation via mesh | ⏸️ DEFERRED (no actual invocation flow) |
| W4.2.4 | WASM distribution | ⏸️ DEFERRED (no mesh upload/distribution flow) |

### Phase 4.3: Admin API Function Deployment

| ID | Description | Status |
|----|-------------|--------|
| W4.3.1 | Upload endpoint | ⏸️ DEFERRED (only static file upload exists) |
| W4.3.2 | File manager | ✅ COMPLETED (FileManager at src/static_files/file_manager.rs) |
| W4.3.3 | Versioning | ❌ NOT NEEDED (WebDAV at src/http/webdav.rs provides versioning) |

---

## Wave 5: Edge Caching and Image Poison

**Status**: ✅ COMPLETED (partial)

### Phase 5.1: Core Infrastructure Fixes

| ID | Description | Status |
|----|-------------|--------|
| W5.1.1 | Broadcast config to edges | ✅ COMPLETED |
| W5.1.2 | Apply received preferences | ✅ COMPLETED |
| W5.1.3 | Protocol message update | ✅ COMPLETED |

### Phase 5.2: Edge HTTP Response Caching

| ID | Description | Status |
|----|-------------|--------|
| W5.2.1 | Edge cache implementation | ✅ COMPLETED |
| W5.2.2 | Cache key computation | ✅ COMPLETED |
| W5.2.3 | MeshProxy integration | ✅ COMPLETED |

### Phase 5.3: Edge Static Caching

| ID | Description | Status |
|----|-------------|--------|
| W5.3.1 | Static cache implementation | ✅ COMPLETED (edge_cache configs, store_record_edge_cache exists) |
| W5.3.2 | Cache invalidation | ✅ COMPLETED (invalidate_by_pattern at proxy_cache/store.rs) |

### Phase 5.4: DHT Image Poison

| ID | Description | Status |
|----|-------------|--------|
| W5.4.1 | DHT remains primary | ✅ COMPLETED |
| W5.4.2 | Dual config priority | ✅ COMPLETED (SiteImagePoisonConfig merges with DHT) |

---

## Wave 6: Honeypot & Threat Intelligence

### Phase 6.1: Port Honeypot Fix

| ID | Description | Status |
|----|------------|--------|
| W6.1.1 | Enable standalone publishing | ✅ COMPLETED |

### Phase 6.2: HTTP Honeypot

| ID | Description | Status |
|----|-------------|--------|
| W6.2.1 | Document by-design behavior | ✅ COMPLETED |

---

## Wave 7: YARA & Threat Intel Distribution

### Phase 7.1: Propagation Speed

| ID | Description | Status |
|----|------------|--------|
| W7.1.1 | Add YARA mesh broadcast | ✅ COMPLETED |

### Phase 7.2: Security Enhancements

| ID | Description | Status |
|----|------------|--------|
| W7.2.1 | Enforce trusted signers | ✅ COMPLETED |
| W7.2.2 | Timestamp bounds check | ✅ COMPLETED |

---

## Wave 8: Mesh & DHT Architecture

### Phase 8.1: High Priority

| ID | Description | Status |
|----|------------|--------|
| W8.1.1 | Fix verified_upstream_cache TTL (30s → 300s) | ✅ COMPLETED |
| W8.1.2 | DNS serving docs update | ✅ COMPLETED |

### Phase 8.2: Medium Priority (Backlog)

| ID | Description | Status |
|----|-------------|--------|
| W8.2.1 | Remove edge_can_respond_privileged bypass | ⏸️ DEFERRED (warning added, bypass not removed) |
| W8.2.2 | Remove verified_upstream from edge keys | ⏸️ DEFERRED (still used in topology.rs) |

---

## Wave 9: OpenAPI Improvements

**Status**: ✅ COMPLETED (partial)

### Phase 9.1: Critical

| ID | Description | Status |
|----|-------------|--------|
| W9.1.1 | Add security scheme definitions | ⏸️ DEFERRED (requires per-handler modification, OpenAPI spec lacks components/securitySchemes) |
| W9.1.2 | Add server URL definitions | ✅ COMPLETED |
| W9.1.3 | Add parameter descriptions | ✅ COMPLETED |

### Phase 9.2: High Priority

| ID | Description | Status |
|----|-------------|--------|
| W9.2.1 | Add example values to schemas | ✅ COMPLETED (partial - few examples exist in handlers/stats.rs) |
| W9.2.2 | Add deprecation markers | ✅ COMPLETED (none needed) |
| W9.2.3 | Document rate limiting | ✅ COMPLETED (429 responses exist) |
| W9.2.4 | Add validation tests | ✅ COMPLETED |

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

# NEW IMPLEMENTATION PLANS (Waves A-G)

---

## Wave A: Mesh and DHT Subsystem Improvements

**Source**: plan3.md

**Objectives**:
- **Refine Node Roles**: Formalize role-based capabilities, ensuring DNS server functionality is restricted to Global nodes.
- **Strengthen Security Model**: Enhance the Global-as-CA attestation for all node types, particularly third-party Edge nodes.
- **Optimize Scalability**: Improve hierarchical routing and DHT sharding for larger network sizes.
- **Increase Robustness**: Implement more sophisticated reputation-based gating and adaptive quorum mechanisms.

### Phase A.1: Security & Attestation (Audit/Fixes)

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.1.1 | Audit `DhtAccessControl` and `peer_auth.rs` | src/mesh/ | 📋 PLANNING |
| A.1.2 | Ensure DNS restrictions are fully enforced in `MeshTransport` | src/mesh/transport.rs | 📋 PLANNING |
| A.1.3 | Global-Only DNS: Update `MeshTransport` and `DnsRegistry` to verify `GLOBAL` role flag before responding to anycast registration or zone sync requests | src/mesh/ | 📋 PLANNING |

### Phase A.2: Multi-Role & Capability-Based Enforcement

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.2.1 | Multi-Role Flexibility: Ensure EDGE \| ORIGIN can proxy through mesh to multiple origin services while serving as edge caching point | src/mesh/ | 📋 PLANNING |
| A.2.2 | Global-as-CA: Extend `MeshCertManager` to handle delegation, allowing Global nodes to issue short-lived "Capability Certificates" | src/mesh/cert.rs | 📋 PLANNING |

### Phase A.3: Organization & Tier Key Management

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.3.1 | Hierarchical Trust: Formalize relationship between `GENESIS_ORG` and other organizations | src/mesh/config_identity.rs | 📋 PLANNING |
| A.3.2 | Tier Key Scoping: Restrict tier keys to specific geographic regions or mesh IDs | src/mesh/tier_key_encryption.rs | 📋 PLANNING |

### Phase A.4: Scalability & Routing Optimizations

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.4.1 | Regional Hub Optimization: Use latency-based clustering instead of geographic distance | src/mesh/dht/routing/ | 📋 PLANNING |
| A.4.2 | Bloom Filter Routing: Implement `MeshBloomFilter` for hierarchical routing | src/mesh/dht/ | 📋 PLANNING |
| A.4.3 | Adaptive Sharding: Transition `ShardedRecordStore` to dynamic sharding | src/mesh/dht/record_store.rs | 📋 PLANNING |
| A.4.4 | Hot-Key Mitigation: Proactive replication for frequently accessed DHT records | src/mesh/dht/ | 📋 PLANNING |

### Phase A.5: Robustness & Reputation

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.5.1 | Proof-of-Uptime: Award reputation based on continuous, verified uptime via periodic heartbeats | src/mesh/ | 📋 PLANNING |
| A.5.2 | Sybil Resistance: Integrate `validate_edge_node_pow` more deeply into connection lifecycle | src/mesh/peer_auth.rs | 📋 PLANNING |
| A.5.3 | Slash Events: Implement `SlashEvent` messages for Global nodes to broadcast when Edge node is detected providing malicious data | src/mesh/ | 📋 PLANNING |
| A.5.4 | Weighted Quorums: Adjust quorum requirements based on node reputation | src/mesh/dht/quorum.rs | 📋 PLANNING |
| A.5.5 | Degraded Quorum Safety: Formalize `enable_degraded_quorum` logic for network partitioning scenarios | src/mesh/dht/ | 📋 PLANNING |

### Phase A.6: Security Model Hardening

| ID | Description | File | Status |
|----|-------------|------|--------|
| A.6.1 | Hardware-Backed Identity: Support TPM/Secure Enclave based identity for Global nodes | src/mesh/ | 📋 PLANNING |
| A.6.2 | Origin Attestation Refresh: Mandatory periodic refreshing of `global_node_attestation_sig` for Origin nodes | src/mesh/discovery.rs | 📋 PLANNING |
| A.6.3 | Strict Key Prefixing: Audit and enforce strict key prefixes in `DhtAccessControl` | src/mesh/dht/record_store_crud.rs | 📋 PLANNING |
| A.6.4 | Value Encryption: Mandatory encryption for sensitive DHT values using `TierKeyEncryption` | src/mesh/tier_key_encryption.rs | 📋 PLANNING |

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
| B.1.1 | Define `PluginType` enum (Wasm, Axum, Serverless) | src/plugin/mod.rs | 📋 PLANNING |
| B.1.2 | Implement `PluginRegistry` with unified storage | src/plugin/mod.rs | 📋 PLANNING |
| B.1.3 | Refactor `PluginManager` to use `PluginRegistry` | src/plugin/mod.rs | 📋 PLANNING |
| B.1.4 | Update `PluginManagerLifecycle` for unified hot-reload | src/plugin/mod.rs | 📋 PLANNING |
| B.1.5 | Add `PluginConfig` to `SiteConfig` | src/config/site/mod.rs | 📋 PLANNING |
| B.1.6 | Map site-specific plugin env vars during invocation | src/plugin/wasm_runtime.rs | 📋 PLANNING |

### Phase B.2: ABI Standardization & Developer Experience

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.2.1 | Implement `maluwaf-guest-sdk` crate for Rust plugins | (new crate) | 📋 PLANNING |
| B.2.2 | Refactor `handle_request` to use structured response header | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| B.2.3 | Add support for streaming response bodies in serverless | src/serverless/manager.rs | 📋 PLANNING |
| B.2.4 | Implement initial support for `wasi-http:proxy` world | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| B.2.5 | Transition to WASM Component Model (WIT) | src/plugin/wasm_runtime.rs | 📋 PLANNING |

### Phase B.3: Security & Isolation

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.3.1 | Implement per-plugin allowlist for `get_env` keys | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| B.3.2 | Add restricted network access for WASM (WASI-socket) | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| B.3.3 | Prototype IPC bridge for `AxumDynamic` backends | src/plugin/axum_loader.rs | 📋 PLANNING |
| B.3.4 | Implement watchdog for external plugin processes | src/plugin/mod.rs | 📋 PLANNING |

### Phase B.4: Mesh & Distribution Enhancements

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.4.1 | Add Ed25519 signature verification for mesh plugins | src/mesh/wasm_dist.rs | 📋 PLANNING |
| B.4.2 | Implement content-addressed storage (CAS) for modules | src/mesh/wasm_dist.rs | 📋 PLANNING |
| B.4.3 | Add delta-compression for module updates | src/mesh/wasm_dist.rs | 📋 PLANNING |

### Phase B.5: Observability & Telemetry

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.5.1 | Add Prometheus metrics for Axum plugin request counts | src/plugin/axum_loader.rs | 📋 PLANNING |
| B.5.2 | Implement `tracing` spans across plugin boundary | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| B.5.3 | Add per-function latency histograms for serverless | src/serverless/manager.rs | 📋 PLANNING |

### Phase B.6: Native Plugin Sandboxing (Out-of-Process)

| ID | Description | File | Status |
|----|-------------|------|--------|
| B.6.1 | Worker Process Pattern: Allow Axum plugins to run in dedicated child process | src/plugin/axum_loader.rs | 📋 PLANNING |
| B.6.2 | Shared Memory IPC: Use shared memory for high-performance request/response handoff | src/plugin/ | 📋 PLANNING |
| B.6.3 | Unix Domain Sockets (Fallback): Use UDS for control plane and small payload transfers | src/plugin/ | 📋 PLANNING |
| B.6.4 | Process Isolation: Use namespaces or cgroups to limit plugin worker resources | src/plugin/ | 📋 PLANNING |

---

## Wave C: Web Application Stack Enhancements

**Source**: plan6.md

### Phase C.1: Unified Theme & Directory Viewer

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.1.1 | Mobile Responsiveness: Enhance `ThemeRenderer` CSS for responsive directory listing | src/theme/renderer.rs | 📋 PLANNING |
| C.1.2 | Metadata Expansion: Add MIME type icons, SHA256 hashes, file permissions to `DirectoryEntry` | src/theme/dir_listing.rs | 📋 PLANNING |
| C.1.3 | Configurable Themes: Expose `ThemePreset` and custom color overrides in `[[site.static.locations]]` | src/config/site/static_files.rs | 📋 PLANNING |
| C.1.4 | Theme Inheritance: Allow location to inherit global site theme or define its own | src/theme/ | 📋 PLANNING |
| C.1.5 | Admin UI Consistency: Add "File Manager" view using same backend JSON format | admin-ui/ | 📋 PLANNING |

### Phase C.2: PHP & FastCGI Hardening

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.2.1 | Themed Error Pages: Return themed error page when PHP/FastCGI backend is down | src/http/server.rs | 📋 PLANNING |
| C.2.2 | Health Check Integration: Map FastCGI pool health status to Admin UI dashboard | src/fastcgi/pool.rs, admin-ui/ | 📋 PLANNING |
| C.2.3 | Active Background Health Checks: PHP-FPM socket failover | src/php/mod.rs | 📋 PLANNING |
| C.2.4 | Environment Variable Injection: Pass custom env vars to FastCGI backends via site config | src/config/site/backend.rs | 📋 PLANNING |

### Phase C.3: WASM Application Platform

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.3.1 | WASI Support Expansion: Enable WASI by default for serverless functions | src/serverless/manager.rs | 📋 PLANNING |
| C.3.2 | Streaming Body Support: WASM ABI for streaming request/response bodies | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| C.3.3 | Routing Enhancements: Wildcard routing and path rewriting before WASM | src/serverless/routing.rs | 📋 PLANNING |

### Phase C.4: Granian Deployment & Python Ecosystem

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.4.1 | Virtualenv Management: Auto-create virtual environment if one doesn't exist | src/app_server/granian.rs | 📋 PLANNING |
| C.4.2 | Log Aggregation: Pipe Granian STDOUT/STDERR to MaluWAF unified logging with site-id attribution | src/app_server/granian.rs | 📋 PLANNING |
| C.4.3 | Granian Dashboard: Admin UI section for running Granian workers, CPU/memory, manual restart | admin-ui/ | 📋 PLANNING |

### Phase C.5: Unified "App Server" Configuration

| ID | Description | File | Status |
|----|-------------|------|--------|
| C.5.1 | Magic Defaults: Smart Detection for `default_root` if `site.php` or `site.granian` defined | src/config/site/mod.rs | 📋 PLANNING |
| C.5.2 | Multi-App Orchestration: Route to different App Stacks based on path (/api -> WASM, /blog -> PHP) | src/router.rs | 📋 PLANNING |

---

## Wave D: Serverless Architecture Improvements

**Source**: plan7.md

**Background**: Current serverless functions are local-only. Goal is distributed edge-computing platform with mesh-wide discovery and routing.

### Phase D.1: Standalone Optimization & ABI Expansion

| ID | Description | File | Status |
|----|-------------|------|--------|
| D.1.1 | Fast-Path Routing: Add `serverless_only = true` config to bypass L7 WAF pipeline | src/config/site.rs, src/router.rs | 📋 PLANNING |
| D.1.2 | ABI Enhancements: Add `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event` host functions | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| D.1.3 | Documentation: Update docs/WASM-ABI.md for new capabilities | docs/WASM-ABI.md | 📋 PLANNING |

### Phase D.2: Mesh Integration & Function Discovery

| ID | Description | File | Status |
|----|-------------|------|--------|
| D.2.1 | Origin Role Definition: Extend `MeshNodeRole` with `SERVERLESS_ORIGIN` flag | src/mesh/config.rs | 📋 PLANNING |
| D.2.2 | DHT Registration: Register `node_id` as active provider when node loads function | src/mesh/transport_peer.rs, src/serverless/manager.rs | 📋 PLANNING |
| D.2.3 | Hierarchical Routing Integration: Treat serverless function names as routable upstreams | src/mesh/hierarchical_routing.rs | 📋 PLANNING |

### Phase D.3: Mesh-Wide Remote Execution (Proxying)

| ID | Description | File | Status |
|----|-------------|------|--------|
| D.3.1 | Protocol Extension: Add `Serverless` variant to `UpstreamProtocol` | src/mesh/protocol.rs | 📋 PLANNING |
| D.3.2 | Remote Execution Dispatch: If `find_matching_route` fails locally, query mesh for provider and forward | src/serverless/manager.rs | 📋 PLANNING |
| D.3.3 | Proxy Handler Updates: Handle incoming remote execution requests securely | src/mesh/proxy.rs | 📋 PLANNING |

### Phase D.4: Event-Driven Triggers

| ID | Description | File | Status |
|----|-------------|------|--------|
| D.4.1 | Event Subscription: Functions can subscribe to mesh event topics | src/serverless/manager.rs | 📋 PLANNING |
| D.4.2 | Event Dispatch: Dispatch serialized payload to subscribed WASM functions | src/mesh/transport_peer.rs | 📋 PLANNING |

### Verification

- **Standalone Fast-Path Test**: Verify `serverless_only` site bypasses attack detector with lower latency
- **ABI Expansion Test**: Create test WASM module that queries DHT and validates response
- **Remote Execution Test**: Deploy Edge and Origin nodes, send function request to Edge, verify proxy and execution
- **Event Dispatch Test**: Trigger mock threat event, verify subscribed function executes

---

## Wave E: Edge Node Caching and Image Poisoning

**Source**: plan8.md

**Objective**: Enforce clear separation - origin publishes preferences to DHT, edge applies transformations and caches.

### Phase E.1: Origin Node Rectification (Mesh Mode)

| ID | Description | File | Status |
|----|-------------|------|--------|
| E.1.1 | Remove `apply_response_transforms` method from origin node | src/mesh/transport_peer.rs | 📋 PLANNING |
| E.1.2 | Simplify `handle_http_proxy_stream` to send raw `full_response` back to edge | src/mesh/transport_peer.rs | 📋 PLANNING |

### Phase E.2: Standalone Mode Configuration Fix

| ID | Description | File | Status |
|----|-------------|------|--------|
| E.2.1 | Modify `apply_image_poisoning` to accept optional `SiteImagePoisonConfig` reference | src/http/server.rs | 📋 PLANNING |
| E.2.2 | Pass configuration fields to `PoisonImageClient` instead of hardcoding `None` | src/http/server.rs | 📋 PLANNING |
| E.2.3 | Update all call sites to pass appropriate config (DHT via `MeshTransportManager` or `site_config`) | src/http/server.rs | 📋 PLANNING |

### Phase E.3: Edge Node Verification

| ID | Description | File | Status |
|----|-------------|------|--------|
| E.3.1 | Verify `transform_response` retrieves preferences from `transport_manager` | src/mesh/proxy.rs | 📋 PLANNING |
| E.3.2 | Verify edge applies transforms and caches result using DHT transform cache | src/mesh/proxy.rs | 📋 PLANNING |

### Verification

- **Mesh Mode Validation**: Deploy origin + edge, confirm transformations only by edge, not origin
- **Standalone Validation**: Single node uses site config level/intensity, not defaults

---

## Wave F: YARA Rules and File Upload Security

**Source**: plan9.md

**Objective**: Fix mesh broadcast bottleneck and integrate malware detection with threat intel.

### Phase F.1: Fix Mesh Forwarder Broadcast Filter

| ID | Description | File | Status |
|----|-------------|------|--------|
| F.1.1 | Update forwarder to selectively apply role filter based on message type | src/worker/unified_server.rs | 📋 PLANNING |
| F.1.2 | Use `None` role filter for announcements reaching all nodes (YaraRuleAnnounce, ThreatAnnounce, etc.) | src/worker/unified_server.rs | 📋 PLANNING |
| F.1.3 | Keep `Some(MeshNodeRole::GLOBAL)` filter for submissions/requests meant only for global | src/worker/unified_server.rs | 📋 PLANNING |

### Phase F.2: Integrate Malware Detection with Threat Intel (HTTP)

| ID | Description | File | Status |
|----|-------------|------|--------|
| F.2.1 | When `UploadValidator` detects malware, extract client IP | src/http/server.rs | 📋 PLANNING |
| F.2.2 | Call `threat_intel.announce_local_block(client_ip, reason, ttl, site_scope)` | src/http/server.rs | 📋 PLANNING |

### Phase F.3: Integrate Malware Detection with Threat Intel (TLS)

| ID | Description | File | Status |
|----|-------------|------|--------|
| F.3.1 | Apply same logic as F.2 for HTTPS uploads | src/tls/server.rs | 📋 PLANNING |

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
| G.1.1 | Wasmtime (RUSTSEC-2026-0096, RUSTSEC-2026-0095): Add `[patch.crates-io]` block to force wasmtime 42.0.2 | Cargo.toml | 📋 PLANNING |
| G.1.2 | KyberSlash (RUSTSEC-2023-0079): Remove `pqc_kyber`, replace with `ml-kem` crate | src/wasm_pow/Cargo.toml, src/wasm_pow/src/lib.rs | 📋 PLANNING |
| G.1.3 | Marvin Attack (RUSTSEC-2023-0071): Update `rsa` from 0.9 to 0.10.x | Cargo.toml | 📋 PLANNING |

### Phase G.2: Replacing Unmaintained Crates

| ID | Description | File | Status |
|----|-------------|------|--------|
| G.2.1 | `proc-macro-error` (RUSTSEC-2024-0370): Update utoipa to 5.4.0 | Cargo.toml | 📋 PLANNING |
| G.2.2 | Refactor OpenAPI schema definitions for Utoipa 5 strict type checking | src/admin/ | 📋 PLANNING |
| G.2.3 | Update yew to 0.23.0 in admin-ui | admin-ui/Cargo.toml | 📋 PLANNING |
| G.2.4 | `bincode` (RUSTSEC-2025-0141): Update gloo to 0.12.0 | admin-ui/Cargo.toml | 📋 PLANNING |
| G.2.5 | `atomic-polyfill` (RUSTSEC-2023-0089): Verify removal via wasmtime patch and postcard update | Cargo.toml | 📋 PLANNING |

### Phase G.3: Modernizing Outdated Crates

| ID | Description | File | Status |
|----|-------------|------|--------|
| G.3.1 | `isbot`: Update from 0.1 to 1.x and adapt bot detection API | Cargo.toml | 📋 PLANNING |
| G.3.2 | `lightningcss`: Update from 1.0.0-alpha.71 to stable release | Cargo.toml | 📋 PLANNING |
| G.3.3 | `sysinfo`: Update from 0.32 to 0.33 and adapt stat gathering logic | Cargo.toml | 📋 PLANNING |
| G.3.4 | `axum`: Ensure workspace uses latest 0.8.9 via cargo update | Cargo.toml | 📋 PLANNING |

### Verification

1. **Security Validation**: Run `cargo audit` to confirm CVE resolution
2. **Compilation Check**: Execute `cargo check --workspace --all-features`
3. **Wasmtime Patch Stability**: Run test suite observing yara-x integration tests
4. **Architecture Verification**: Run `cargo run -- --configtest` to verify Overseer/Master/Worker boot

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