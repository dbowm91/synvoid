# MaluWAF Implementation Plan

**Last updated**: 2026-04-18
**Status**: ACTIVE PLANNING - All critical items completed, deferred items consolidated

---

## Overview

This is the consolidated implementation plan for MaluWAF. All critical security fixes, performance improvements, WASM enhancements, honeypot fixes, edge transform fixes, and test coverage have been completed. This document tracks remaining deferred items organized by category and priority for implementation.

**Status Legend**:
- ✅ COMPLETED - Item fully implemented and verified (all items prior to 2026-04-18)
- 🔶 WAVE 1 - Can be implemented in parallel with sub-agents
- 🔶 WAVE 2 - Can be implemented in parallel with sub-agents
- 🔶 WAVE 3 - Can be implemented in parallel with sub-agents
- ⏸️ DEFERRED - Requires further investigation or blocked
- ❌ NOT RECOMMENDED - Investigation shows risk outweighs benefit

---

## Quick Reference Summary

### Previously Completed (as of 2026-04-18)
- Security: S-1 through S-10, S-11, S-13, S-18 all fixed
- Performance: P1.1, P1.2, P1.3, P2.1, P2.2, P2.3, P2.4, P3 all fixed
- WASM: W1-W10 all fixed
- Honeypot/Threat: H1-H4 all fixed
- Edge Transform: E1-E6 all verified/completed
- Reverse Proxy/WAF: All items fixed
- Testing: T1-T5, T4 (WAF detection integration tests) all fixed
- Code Quality: C1, C2, O2, O3 fixed
- OpenAPI: Fully implemented
- Web Phases 1-5: All completed
- Admin 1-7: All completed

### Remaining Deferred Items
- **G1**: Full process tree not tested (requires complex process spawn infrastructure)
- **G3**: Upgrade/rollback protocol not tested (complex testing scenario)
- **G8**: Windows named pipe path not tested (requires Windows CI)
- **Admin 8-15**: Various UI improvements (existing implementations adequate)
- **O1**: lib.rs public API - NOT RECOMMENDED

---

## Wave 1: Security P0-P2 (Critical/High Priority)

These items are security-critical or high-impact. They should be implemented first in parallel where possible.

### Wave 1A: Critical Vulnerabilities (P0)

| ID | Issue | Location | Type |
|----|-------|----------|------|
| P0-1 | IPC Signing Not Enforced on Receive Path | `src/process/ipc_transport.rs:342-385` | Security |
| P0-2 | CSRF Protection Bypass via Session Fixation | `src/admin/middleware.rs:125-130`, `src/admin/state.rs:628-648` | Security |
| P0-3 | DNSSEC RDATA Validation Bypass | `src/dns/update.rs:472-476` | Security |
| P0-4 | DNS Exists Prerequisite Bypass | `src/dns/update.rs:461-479` | Security |
| P0-5 | Port Honeypot No Immediate IP Blocking | `src/honeypot_port/listener.rs:169-269` | Security |
| P0-6 | Threat Intel signer=None Bypasses Verification | `src/mesh/threat_intel.rs:742-766` | Security |
| P0-7 | UpdateKeyExchange Only Self-Signed | `src/mesh/transport_global.rs:29-49` | Security |
| P0-8 | No source_node_id Verification in Threats | `src/mesh/threat_intel.rs:735-768` | Security |
| P0-9 | TSIG Replay Attack Prevention Missing | `src/dns/tsig.rs:74-171` | Security |
| P0-10 | Dynamic Update Prerequisite Logic Inversion | `src/dns/update.rs:461-479` | Security |
| P0-11 | PID Spoofing Not Rejected | `src/master/ipc.rs:351-367` | Security |
| P0-12 | Socket Fallback to World-Writable /tmp | `src/process/socket_path.rs:55-58` | Security |
| P0-13 | TOCTOU Race in SlottedIpRateLimiter | `src/waf/ratelimit/core.rs:436-457` | Security |
| P0-14 | Connection Limiter TOCTOU Race | `src/waf/flood/connection_limiter.rs:62-68` | Security |

**Implementation notes for P0**:
- Each fix should be in a separate commit for targeted rollback
- Run `cargo test --test integration_test` after each P0 fix
- If tests fail, rollback immediately before proceeding

### Wave 1B: High Severity (P1)

| ID | Issue | Location | Type |
|----|-------|----------|------|
| P1-1 | OptionalAuth Allows Unauthenticated Access | `src/admin/handlers/common.rs:15` | Auth |
| P1-2 | PID Spoofing Not Rejected | `src/master/ipc.rs:351-367` | Security |
| P1-3 | TSIG MAC Timing Attack | `src/dns/tsig.rs:161-168` | Security |
| P1-4 | AuthRateLimiter Lockout Never Triggers | `src/admin/auth.rs:35-75` | Auth |
| P1-5 | Unsigned DHT Records via Anti-Entropy | `src/mesh/dht/record_store_message.rs:426-427` | Security |
| P1-6 | Port Honeypot Connection Limit IP Blocking | `src/honeypot_port/listener.rs:118-121` | Security |
| P1-7 | Honeypot Hit Counter Unbounded | `src/challenge/honeypot.rs:27-29` | Security |
| P1-8 | Admin Token Verification Bypasses Rate Limiter | `src/admin/auth.rs:24-25`, `src/admin/middleware.rs:76` | Auth |
| P1-9 | Race Condition in AdminRateLimiter | `src/admin/state.rs:53-65` | Auth |
| P1-10 | SQLi/XSS Detector Bypasses Normalizer | `src/waf/attack_detection/mod.rs:287,294` | WAF |
| P1-11 | Open Redirect Encoding Bypass | `src/waf/attack_detection/open_redirect.rs:138-152` | WAF |
| P1-12 | Path Traversal Double-Encoding | `src/waf/attack_detection/path_traversal.rs:30-35` | WAF |
| P1-13 | No Per-User Session Limit | `src/auth/mod.rs:481-494` | Auth |
| P1-14 | No Session Invalidation on Password Change | `src/auth/mod.rs` | Auth |
| P1-15 | SSRF IPv6 Zone ID Bypass | `src/waf/attack_detection/ssrf.rs:260-273` | WAF |
| P1-16 | TLS Passthrough Bypasses WAF | `src/worker/unified_server.rs:307-317` | Security |
| P1-17 | skip_verify Enables Impersonation | `src/http_client/mod.rs:140-158` | Security |
| P1-18 | Route Cached Without Signature Verification | `src/mesh/discovery.rs:716-744` | Security |

### Wave 1C: Medium Severity (P2)

| ID | Issue | Location | Type |
|----|-------|----------|------|
| P2-1 | Transfer-Encoding Obfuscation Bypass | `src/waf/attack_detection/request_smuggling.rs:41-45` | WAF |
| P2-2 | Nonce Cache Eviction Bug | `src/process/ipc_signed.rs:40-56` | Security |
| P2-3 | Threat Intel Sync Accepts Unsigned | `src/mesh/threat_intel.rs:1236-1241` | Security |
| P2-4 | Insecure IPC Key Fallback | `src/process/manager.rs:351-365` | Security |
| P2-5 | Genesis Key Uses StdRng | `src/mesh/config_identity.rs:117-118` | Security |
| P2-6 | Missing Whitespace Normalization | `src/waf/attack_detection/normalizer.rs:272-282` | WAF |
| P2-7 | DNS TTL No Validation | `src/dns/update.rs:147-152` | DNS |
| P2-8 | Cache Fingerprint Threshold Low | `src/dns/cache.rs:179-186` | DNS |
| P2-9 | Compression Pointer OOB Access | `src/dns/update.rs:186` | DNS |
| P2-10 | Wildcard AXFR Too Permissive | `src/dns/transfer.rs:50-62` | DNS |
| P2-11 | Quorum Auto-Approve with <3 Global Nodes | `src/mesh/dht/record_store_message.rs:703-709` | Mesh |
| P2-12 | Global Node Unrestricted Write Access | `src/mesh/dht/record_store_crud.rs:85-87` | Mesh |
| P2-13 | Capability Attestation Not Verified | `src/mesh/transport.rs:640-647` | Mesh |
| P2-14 | Stake Weight Not Used in Quorum | `src/mesh/dht/quorum.rs:1-100` | Mesh |
| P2-15 | Routing Table Single Lock Contention | `src/mesh/dht/routing/manager.rs:30` | Mesh |
| P2-16 | Bucket Refresh Without Jitter | `src/mesh/dht/routing/manager.rs:550-560` | Mesh |

---

## Wave 2: Performance, Mesh & WASM Improvements

### Wave 2A: Critical Performance Issues

| ID | Issue | Location | Type |
|----|-------|----------|------|
| P-C0 | find_verified_upstreams O(n) on cache hit | `mesh/topology.rs:739-823` | Performance |
| P-C1 | SlottedIpRateLimiter Mutex contention | `waf/ratelimit/core.rs:434` | Performance |
| P-C2 | OpenRedirectDetector O(74) linear searches | `waf/attack_detection/open_redirect.rs:108-112` | Performance |
| P-C3 | JwtDetector O(14) linear searches | `waf/attack_detection/jwt.rs:186-218` | Performance |
| R1 | CPU Transform Thread Pool Isolation | `src/http/server.rs:2535-2700`, `src/mesh/proxy.rs:1247-1320` | Performance |
| R2 | Mesh Provider Fan-Out Concurrency Limiting | `src/mesh/proxy.rs:767-897` | Performance |

### Wave 2B: High Priority Performance

| ID | Issue | Location | Type |
|----|-------|----------|------|
| P-H1 | is_websocket_upgrade() double to_lowercase() | `http/headers.rs:114-132` | Performance |
| P-H2 | headers_to_filter rebuild per request | `http/server.rs:2367-2383` | Performance |
| P-H3 | XXE triple string allocation | `waf/attack_detection/xxe.rs:25-36` | Performance |
| P-H4 | generate_stealth_timestamp() alloc per response | `http/headers.rs:145-154` | Performance |
| P-H5 | MeshTopology uses tokio::sync::RwLock | `mesh/topology.rs:33,36` | Performance |
| P-H6 | ProxyCache.host_index lock contention | `proxy_cache/store.rs:453` | Performance |
| R3 | Upstream Pool Lock Contention | `src/upstream/pool.rs:287-385` | Performance |
| R4 | WAF Body Collection Before Scanning | `src/http/server.rs:922-1008` | Performance |
| R5 | Router Domain Map Optimization | `src/router.rs:31` | Performance |

### Wave 2C: WASM/Serverless Improvements

| ID | Issue | Location | Type |
|----|-------|----------|------|
| W1 | Route Matching Inconsistency | `src/serverless/routing.rs` | Serverless |
| W2 | Regex Compilation Per-Match | `src/serverless/routing.rs` | Serverless |
| W3 | No Route Conflict Detection | `src/serverless/routing.rs` | Serverless |
| W4 | No Visibility into Pool vs Direct Mode | `src/serverless/instance_pool.rs` | Serverless |
| W5 | Missing Health Checks for Instance Pool | `src/serverless/instance_pool.rs` | Serverless |
| W6 | Route Update Inefficiency | `src/serverless/manager.rs` | Serverless |
| W7 | CPU Fuel Disabled by Default in Pool | `src/serverless/instance_pool.rs:142` | Serverless |

### Wave 2D: Distributed Serverless (Mesh Mode)

| ID | Issue | Location | Type |
|----|-------|----------|------|
| DS1 | ServerlessFunctionAnnounce Not Wired to DHT | `src/mesh/transport_peer.rs` | Serverless |
| DS2 | No Serverless Function Discovery Mechanism | `src/mesh/transport_peer.rs` | Serverless |
| DS3 | Origin Cannot Execute Serverless via Mesh Transport | `src/mesh/transport_peer.rs` | Serverless |
| DS4 | No Serverless DHT Key Type | `src/mesh/dht/keys.rs` | Serverless |
| DS5 | No Configuration Schema for Local Serverless | `src/mesh/config.rs` | Serverless |

---

## Wave 3: Infrastructure & Polish

### Wave 3A: Edge Caching & Mesh

| ID | Issue | Location | Type |
|----|-------|----------|------|
| C1 | proxy_cache_preferences ignored with `_` prefix | `admin/state.rs:500` | Mesh |
| C2 | MeshProxy.proxy_cache never used | `mesh/proxy.rs:75,996-1088` | Mesh |
| C3 | No callback mechanism to apply preferences | `transports/manager.rs` | Mesh |
| C4 | Cache-Control headers not processed | `mesh/proxy.rs:1091-1369` | Mesh |

### Wave 3B: YARA/ThreatIntel Distribution

| ID | Issue | Location | Type |
|----|-------|----------|------|
| Y1 | YaraRulesManager no start_background_tasks() | `src/mesh/yara_rules.rs` | ThreatIntel |
| Y2 | YARA sync uses get_all_records() not get_by_prefix() | `src/mesh/yara_rules.rs:434` | ThreatIntel |
| Y3 | YARA records not using SignedRecordType | `src/mesh/dht/keys.rs:621-622` | ThreatIntel |
| Y4 | FileManager scan_on_upload disabled by default | `src/static_files/file_manager.rs:107` | Security |
| Y5 | YARA Rule Reload Errors Silently Ignored | `src/static_files/file_manager.rs:791` | Security |
| H1 | Port honeypot mesh publishing not in standalone | `src/worker/unified_server.rs:1082-1089` | ThreatIntel |
| H2 | Silent DHT Publish Failures | `src/mesh/threat_intel.rs:655-664` | ThreatIntel |
| H3 | Silent DHT Sync Failures | `src/mesh/threat_intel.rs:1625-1626` | ThreatIntel |
| H4 | Background Tasks Waste Resources in Standalone | `src/mesh/threat_intel.rs:1596-1657` | ThreatIntel |

### Wave 3C: Code Quality & Documentation

| ID | Issue | Location | Type |
|----|-------|----------|------|
| CQ1 | Empty Windows Platform Stub | `src/platform/windows.rs` | Code Quality |
| CQ2 | Misleading WireGuard "Stub" Log Message | `src/tunnel/wireguard/userspace.rs:207` | Code Quality |
| CQ3 | Reserved Future Mesh Transport Modules | `src/mesh/transport_*.rs` | Code Quality |
| CQ4 | Other Dead Code Modules | various | Code Quality |
| D1 | ARCHITECTURE.md - Complete Rewrite | `docs/ARCHITECTURE.md` | Documentation |
| D2 | API_REFERENCE.md - Missing ~70 endpoints | `docs/API_REFERENCE.md` | Documentation |
| D3 | STATIC_FILES.md - Config corrections | `docs/STATIC_FILES.md` | Documentation |
| D4 | PROXY_CACHE.md - Configuration rewrite | `docs/PROXY_CACHE.md` | Documentation |
| D5 | WAF_MESH.md - Remove obsolete WireGuard | `docs/WAF_MESH.md` | Documentation |
| D6 | ATTACK_DETECTION.md - Accuracy + Depth | `docs/ATTACK_DETECTION.md` | Documentation |
| D7 | SERVERLESS.md - Fix ABI + Add backends | `docs/SERVERLESS.md` | Documentation |
| D8 | DNS docs - dns-mesh-integration.md updates | `docs/` | Documentation |

### Wave 3D: Admin & Testing

| ID | Issue | Location | Type |
|----|-------|----------|------|
| A1 | Missing Security Configuration UI | `admin-ui/src/pages/settings.rs` | Admin |
| A2 | Missing Tunnel/VPN Configuration UI | `admin-ui/src/pages/settings.rs` | Admin |
| A3 | Missing Plugins Configuration UI | `admin-ui/src/pages/settings.rs` | Admin |
| A4 | Metrics Configuration UI Incomplete | `admin-ui/src/pages/settings.rs` | Admin |
| A5 | Traffic Shaping Configuration UI Incomplete | `admin-ui/src/pages/settings.rs` | Admin |
| O1 | OpenAPI redundant routing | `src/admin/mod.rs:519`, `openapi.rs:323` | OpenAPI |
| O2 | OpenAPI no validation test | `src/admin/openapi.rs` | OpenAPI |
| T1 | Drain Test Hanging | `tests/drain_e2e_test.rs` | Testing |
| T2 | DNS Cache len() returns zero | `src/dns/recursive_cache.rs` | Testing |
| T3 | Multi-Worker Drain Sequence | `tests/drain_e2e_test.rs` | Testing |
| T4 | Process Manager Restart Logic | `src/process/manager.rs` | Testing |
| T5 | Inter-Component Config Broadcast | `src/process/ipc.rs` | Testing |

### Wave 3E: Web App Stack Improvements

| ID | Issue | Location | Type |
|----|-------|----------|------|
| S1 | Theme preset accessibility | `src/theme/dir_listing.rs` | Web |
| S3 | File preview support | `src/static_files/directory.rs` | Web |
| S4 | Drag-and-drop file upload UI | `src/theme/dir_listing.rs` | Web |
| S5 | Archive extraction UI | `src/theme/dir_listing.rs` | Web |
| P1 | PHP-FPM status page support | `src/php/mod.rs` | Web |
| P2 | PHP-FPM pm configuration exposure | `src/config/site/backend.rs` | Web |
| F1 | FastCGI status page endpoint | `src/fastcgi/pool.rs` | Web |
| G1 | Granian enhanced logging configuration | `src/app_server/granian.rs` | Web |
| G2 | Granian requirements.txt improvements | `src/app_server/granian.rs` | Web |
| Web4-1 | Sorting options for directory listing | `src/theme/dir_listing.rs` | Web |
| Web4-2 | Pagination for directory listing | `src/theme/dir_listing.rs` | Web |
| Web4-3 | File type filtering | `src/theme/dir_listing.rs` | Web |
| Web5-1 | Consolidate directory listing CSS | `src/theme/renderer.rs` | Web |
| Web5-2 | Breadcrumb navigation | `src/theme/dir_listing.rs` | Web |

### Wave 3F: Dependency Security

| ID | Issue | Location | Type |
|----|-------|----------|------|
| DS-1 | wasmtime via yara-x (Multiple CVEs) | `Cargo.toml` | Dependencies |
| DS-2 | Update SECURITY.md | `SECURITY.md` | Dependencies |
| DS-3 | yew 0.23 upgrade consideration | `admin-ui/Cargo.toml` | Dependencies |
| DS-4 | Monitor pqc_kyber for ML-KEM | `wasm-pow` | Dependencies |

---

## Deferred Items (No Timeline)

### Testing Infrastructure

| ID | Issue | Reason |
|----|-------|--------|
| G1 | Full process tree testing | Requires complex process spawn infrastructure |
| G3 | Upgrade/rollback protocol testing | Complex testing scenario |
| G8 | Windows named pipe path testing | Requires Windows CI |

### Admin UI Improvements

| ID | Issue | Reason |
|----|-------|--------|
| Admin 8 | Additional configuration pages | Nice-to-have, not critical |
| Admin 9-15 | Various UI/UX enhancements | Existing implementations adequate |

### Not Recommended

| ID | Issue | Reason |
|----|-------|--------|
| O1 | lib.rs public API refactoring | 68% of modules unused externally; effort vs. benefit not justified |

---

## Implementation Order Guidelines

### Wave 1 (Security) - Suggested Parallelization
- **Sub-agent 1**: P0-1 through P0-5 (Auth/Admin security fixes)
- **Sub-agent 2**: P0-6 through P0-10 (Mesh/DNS security fixes)
- **Sub-agent 3**: P0-11 through P0-14, P1-1 through P1-5 (IPC/RL security fixes)
- **Sub-agent 4**: P1-6 through P1-18 (High priority remaining)

### Wave 2 (Performance/WASM) - Suggested Parallelization
- **Sub-agent 5**: P-C0 through P-C3 (Critical performance fixes)
- **Sub-agent 6**: R1, R2, R3 (Reverse proxy scalability)
- **Sub-agent 7**: P-H1 through P-H6 (High priority performance)
- **Sub-agent 8**: WASM improvements (W1-W7, DS1-DS5)

### Wave 3 (Infrastructure/Polish) - Suggested Parallelization
- **Sub-agent 9**: Edge caching (C1-C4), YARA/ThreatIntel (Y1-Y5, H1-H4)
- **Sub-agent 10**: Admin UI improvements (A1-A5, O1-O2)
- **Sub-agent 11**: Testing fixes (T1-T5)
- **Sub-agent 12**: Documentation (D1-D8)
- **Sub-agent 13**: Web stack (S1-S5, P1-P2, F1, G1-G2, Web4-*, Web5-*)
- **Sub-agent 14**: Dependency security (DS-1 through DS-4)
- **Sub-agent 15**: Code quality (CQ1-CQ4)

---

## Verification Commands

```bash
# Run integration tests (fast)
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

# Run cargo audit
cargo audit
```

---

## Historical Context

This plan was consolidated from multiple plan files (plan.md, plan2.md through plan19.md) tracking implementation progress since the project's inception. As of 2026-04-18, all critical security fixes, performance improvements, and feature work has been completed. The remaining items are organized into waves for parallel implementation.

**Last consolidated**: 2026-04-18
