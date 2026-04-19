# MaluWAF Implementation Plan

**Last updated**: 2026-04-19
**Status**: CONSOLIDATED - Planning items from plan2-plan10 merged

---

## Overview

This is the consolidated implementation plan combining items from plan2.md through plan10.md. The main deferred items tracking (original plan.md) remains as reference for already-completed waves.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented and verified
- 📋 PLANNING - Not yet started
- 🔄 IN PROGRESS - Actively being implemented
- ⏸️ DEFERRED - Requires further investigation or blocked
- ❌ NOT RECOMMENDED - Investigation shows risk outweighs benefit

---

## Wave Structure

Items grouped into waves where parallelization is possible:

| Wave | Focus | Sub-Agents Possible |
|------|-------|------------------|
| Wave 1 | Documentation & Documentation Cleanup | Yes - multiple sub-agents |
| Wave 2 | Test Coverage | Yes - multiple sub-agents |
| Wave 3 | Admin Panel UI Parity | Yes - multiple sub-agents |
| Wave 4 | Serverless & Edge Caching | No - dependent on Wave 1-3 |
| Wave 5 | Security & Hardening | Yes - multiple sub-agents |
| Wave 6 | OpenAPI Improvements | Yes - independent |

---

## Wave 1: Documentation Improvements

**Rationale**: Remove outdated content first, then add explanatory docs. Multiple sub-agents can work in parallel.

### Phase 1.1: Remove Outdated WireGuard Content

| ID | Action | File | Status |
|----|--------|------|--------|
| W1.1.1 | Remove WireGuard Tunnel section (keep note) | docs/TUNNELS.md | 📋 PLANNING |
| W1.1.2 | Remove WireGuard config example | docs/CONFIGURATION.md | 📋 PLANNING |
| W1.1.3 | Remove wireguard from platform table | docs/PLATFORM_SUPPORT.md | 📋 PLANNING |
| W1.1.4 | Update README.md WireGuard claims | README.md | 📋 PLANNING |
| W1.1.5 | Update docs/README.md WireGuard | docs/README.md | 📋 PLANNING |
| W1.1.6 | Fix CHANGELOG.md WireGuard | CHANGELOG.md | 📋 PLANNING |
| W1.1.7 | Update paper.md WireGuard refs | paper.md | 📋 PLANNING |

### Phase 1.2: New Documentation Files

| ID | Description | Status |
|----|------------|--------|
| W1.2.1 | RFC 5011 Trust Anchor doc (docs/RFC5011_TRUST_ANCHOR.md) | 📋 PLANNING |
| W1.2.2 | Threat Intelligence doc (docs/THREAT_INTEL.md) | 📋 PLANNING |

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
| W1.3.1 | TLS/ACME - add PQ config, 0-RTT, passthrough | 📋 PLANNING |
| W1.3.2 | WAF Mesh - DHT distribution, tier keys | 📋 PLANNING |
| W1.3.3 | Bot Protection - PoW 12s, challenge types | 📋 PLANNING |
| W1.3.4 | Attack Detection - decision types | 📋 PLANNING |
| W1.3.5 | DNS/DNSSEC - RFC 5011 integration | 📋 PLANNING |
| W1.3.6 | CONFIG common mistakes section | 📋 PLANNING |

---

## Wave 2: Test Coverage Improvements

**Rationale**: Add unit tests for overseer modules. Multiple sub-agents can work on different phases.

### Phase 2.1: Health Monitoring Tests

**Module**: `src/overseer/health.rs` (877 lines, 0 tests)

| ID | Test Name | Status |
|----|----------|--------|
| W2.1.1 | test_health_status_enum_variants | 📋 PLANNING |
| W2.1.2 | test_worker_readiness_status_default | 📋 PLANNING |
| W2.1.3 | test_enhanced_health_config_defaults | 📋 PLANNING |
| W2.1.4 | test_baseline_comparison_calculation | 📋 PLANNING |
| W2.1.5 | test_shadow_traffic_result_fields | 📋 PLANNING |
| W2.1.6 | test_worker_readiness_status_creation | 📋 PLANNING |

### Phase 2.2: Upgrade Process Tests

**Module**: `src/overseer/upgrade.rs` (1075 lines, 0 tests)

| ID | Test Name | Status |
|----|----------|--------|
| W2.2.1 | test_auto_rollback_config_defaults | 📋 PLANNING |
| W2.2.2 | test_upgrade_mode_detection | 📋 PLANNING |
| W2.2.3 | test_orchestrator_construction | 📋 PLANNING |
| W2.2.4 | test_upgrade_state_transitions | 📋 PLANNING |
| W2.2.5 | test_preflight_validation_logic | 📋 PLANNING |
| W2.2.6 | test_health_check_metrics | 📋 PLANNING |

### Phase 2.3: Rollback Mechanism Tests

**Module**: `src/overseer/rollback.rs` (240 lines, 0 tests)

| ID | Test Name | Status |
|----|----------|--------|
| W2.3.1 | test_rollback_manager_defaults | 📋 PLANNING |
| W2.3.2 | test_rollback_error_display | 📋 PLANNING |
| W2.3.3 | test_rollback_target_construction | 📋 PLANNING |
| W2.3.4 | test_can_rollback_logic | 📋 PLANNING |
| W2.3.5 | test_rollback_target_parsing | 📋 PLANNING |

### Phase 2.4: Socket Handoff Tests

**Module**: `src/overseer/socket_handoff.rs` (635 lines, 1 test)

| ID | Test Name | Status |
|----|----------|--------|
| W2.4.1 | test_socket_handoff_error_types | 📋 PLANNING |
| W2.4.2 | test_handoff_server_construction | 📋 PLANNING |
| W2.4.3 | test_handoff_client_connection_timeout | 📋 PLANNING |
| W2.4.4 | test_handoff_invalid_state_errors | 📋 PLANNING |

---

## Wave 3: Admin Panel UI Parity

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
| W3.4.1 | Rule Feed section | ⏸️ DEFERRED (needs backend API) |
| W3.4.2 | Static Files config section | ✅ COMPLETED (per-site) |
| W3.4.3 | Update search index | ✅ COMPLETED |
| W3.4.4 | Config documentation tooltips | ✅ COMPLETED |

---

## Wave 4: Serverless Architecture

**Status**: ✅ COMPLETED (partial)

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
| W4.2.2 | Function announcement to DHT | ⏸️ DEFERRED (receiver exists, sender not wired) |
| W4.2.3 | Edge invocation via mesh | ⏸️ DEFERRED (mesh message types exist) |
| W4.2.4 | WASM distribution | ⏸️ DEFERRED (infra exists, upload flow missing) |

### Phase 4.3: Admin API Function Deployment

| ID | Description | Status |
|----|-------------|--------|
| W4.3.1 | Upload endpoint | ⏸️ DEFERRED (requires new API work) |
| W4.3.2 | File manager | ⏸️ DEFERRED (requires new API work) |
| W4.3.3 | Versioning | ⏸️ DEFERRED (requires new API work) |

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
| W5.3.1 | Static cache implementation | ⏸️ DEFERRED (requires static-specific design) |
| W5.3.2 | Cache invalidation | ⏸️ DEFERRED (pattern invalidation exists) |

### Phase 5.4: DHT Image Poison

| ID | Description | Status |
|----|-------------|--------|
| W5.4.1 | DHT remains primary | ✅ COMPLETED |
| W5.4.2 | Dual config priority | ⏸️ DEFERRED (site-level config merges DHT) |

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
|----|------------|--------|
| W8.2.1 | Remove edge_can_respond_privileged bypass | ⏸️ DEFERRED |
| W8.2.2 | Remove verified_upstream from edge keys | ⏸️ DEFERRED |

---

## Wave 9: OpenAPI Improvements

**Status**: ✅ COMPLETED (partial)

### Phase 9.1: Critical

| ID | Description | Status |
|----|-------------|--------|
| W9.1.1 | Add security scheme definitions | ⏸️ DEFERRED (requires per-handler modification) |
| W9.1.2 | Add server URL definitions | ✅ COMPLETED |
| W9.1.3 | Add parameter descriptions | ✅ COMPLETED |

### Phase 9.2: High Priority

| ID | Description | Status |
|----|-------------|--------|
| W9.2.1 | Add example values to schemas | ⏸️ DEFERRED (partial - some exist) |
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

- All WireGuard references should be removed from docs (Wave 1)
- Test coverage focused on deterministic logic (Wave 2)
- Admin panel uses existing API handlers, adds UI sections only (Wave 3)
- Serverless builds on existing WASM infrastructure (Wave 4)
- Edge caching adds new components, doesn't modify existing (Wave 5)
- Port honeypot fix is single-line change (Wave 6)
- YARA broadcast similar to threat intel pattern (Wave 7)
- Mesh TTL fix is single-line change (Wave 8)
- OpenAPI improvements are additive (Wave 9)