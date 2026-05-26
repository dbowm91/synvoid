# SynVoid Consolidated Action Plan

**Generated:** 2026-05-26
**Status:** PLANNED
**Consolidated From:** Batch 1 (consolidated_review_plan.md), Batch 2 (proxy/admin/plugin/waf plans), Batch 3 (routing/process_lifecycle/platform/mesh plans), Batch 4 (app_handlers/config/migration plans)

---

## Executive Summary

This document consolidates all action items from four batches of architecture review plans. The items are organized into **8 parallel work waves** plus the **sequential Supervisor Migration** (the longest critical path). All waves 1-5 can execute in parallel and complete before or after migration; only Wave 6 (testing) depends on migration completion.

| Category | Items | Priority |
|----------|-------|----------|
| Documentation Corrections | 35 | Mixed P1-P3 |
| Code Quality/Bugs | 12 | P0-P2 |
| Architecture Documentation | 15 | P1-P2 |
| Supervisor Migration | 1 epic (6 sub-waves) | P0 |

---

## Theme 1: HTTP/2 Behavior Documentation

### 1.1 Fix HTTP/2 Status in Worker Architecture Doc
- **Source:** consolidated_review_plan.md:17 (worker_review_plan.md)
- **File:** `architecture/worker_architecture.md`, Line 13
- **Priority:** P1 (High)
- **Action:** Change from "Currently disabled (`is_http2 = false`)" to "Enabled via ALPN negotiation"
- **Reason:** Code at `src/tls/server.rs:411-487` shows ALPN-based HTTP/2 negotiation on server side

### 1.2 Document HTTP/2 Hardcoded Behavior in Networking Doc
- **Source:** consolidated_review_plan.md:27 (networking.md)
- **File:** `architecture/networking_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Clarify `is_http2 = true` is hardcoded at `src/http_client/mod.rs:893` for upstream connections
- **Reason:** HTTP/2 upstream infrastructure exists but hardcoded request bypasses dynamic detection

### 1.3 HTTP/2 Connection Pooling - ErasedHttpClient Phase 9 Incomplete
- **Source:** proxy_review_plan.md:12-25
- **Location:** `src/http/server.rs:3305`
- **Priority:** P1 (High)
- **Action:** Change `use_erased_client = false` hardcoded to conditional logic based on streaming body detection
- **Bug ID:** Known Issue (Phase 9 incomplete)
- **Verification:** `cargo check --features mesh,dns`

### 1.4 HTTP/2 Multiplexing Non-Functional
- **Source:** proxy_review_plan.md:117-122
- **Location:** `src/http_client/erased_pool.rs:204-206`
- **Priority:** P2 (Medium)
- **Action:** `Http2PooledConnection::is_available()` always returns `false` - implement or document as stub
- **Impact:** Only HTTP/1.1 used for upstream

---

## Theme 2: WAF Pipeline Documentation

### 2.1 Correct WAF Pipeline Stage Order
- **Source:** consolidated_review_plan.md:36 (worker_review_plan.md)
- **File:** `architecture/worker_architecture.md`, Lines 29-35
- **Priority:** P2 (Medium)
- **Action:** Swap stages 6 (Attack Detection) and 7 (Flood Protection)
- **Reason:** Code at `src/waf/mod.rs:476-514` shows flood check (476-484) runs BEFORE attack detection (486-514)

### 2.2 Clarify Bot Protection Inline Challenge
- **Source:** consolidated_review_plan.md:45 (worker_review_plan.md)
- **File:** `architecture/worker_architecture.md`
- **Priority:** P3 (Low)
- **Action:** Clarify challenges come from `challenge_manager.generate_challenge_page()` within `check_bot_protection()`, not as separate stage
- **Code Ref:** `src/waf/mod.rs:634-693`

### 2.3 Document ChallengeWithCookie Decision Variant
- **Source:** waf_review_plan.md:154-157
- **File:** `architecture/waf_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Add `ChallengeWithCookie` to decision types documentation
- **Code Ref:** `src/waf/mod.rs:67-73`

### 2.4 PatternDetector Line Reference Correction
- **Source:** waf_review_plan.md:17-25
- **File:** `architecture/waf_deep_dive.md:51`
- **Priority:** P3 (Low)
- **Action:** Change `src/waf/attack_detection/detector_common.rs:264` → `src/waf/attack_detection/detector_common.rs:293`

---

## Theme 3: DNS Documentation Corrections

### 3.1 Fix Cookie RFC Reference
- **Source:** consolidated_review_plan.md:54 (dns_review_plan.md)
- **File:** `architecture/dns_deep_dive.md`, Line 39
- **Priority:** P1 (High)
- **Action:** Change RFC 8905 to RFC 8905/RFC 7873 - cookies via EDNS option
- **Reason:** Code at `src/dns/cookie.rs:47-48` cites RFC 7873

### 3.2 Remove Non-Existent DnsServerQueryHandler Reference
- **Source:** consolidated_review_plan.md:65 (dns_review_plan.md)
- **File:** `architecture/dns_deep_dive.md`, Line 69
- **Priority:** P1 (High)
- **Action:** Change `DnsServerQueryHandler` to `QueryContext` at lines 419-445

### 3.3 Add DNSSEC Limitations Note
- **Source:** consolidated_review_plan.md:74 (dns_review_plan.md)
- **File:** `architecture/dns_deep_dive.md`
- **Priority:** P1 (High)
- **Action:** Add note about manual wire format construction and lacking compression support
- **Code Ref:** `src/dns/dnssec.rs:1-13`

### 3.4 Document AXFR Record Type Coverage Gaps
- **Source:** consolidated_review_plan.md:83 (dns_review_plan.md)
- **File:** `architecture/dns_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Document missing record types: NAPTR (35), CERT (37), SMMEA (48), DNAME (39)
- **Code Ref:** `src/dns/transfer.rs:829-1019`

### 3.5 Add GOST DS Digest Note
- **Source:** consolidated_review_plan.md:89 (dns_review_plan.md)
- **File:** `architecture/dns_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Note GOST DS digest (type 3) not supported
- **Code Ref:** `src/dns/dnssec_validation.rs:260`

### 3.6 Document Cookie Server Integration Status
- **Source:** consolidated_review_plan.md:98 (dns_review_plan.md)
- **File:** `architecture/dns_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Clarify `cookie_server` field is set to `None` in `DnsServer::clone()`
- **Code Ref:** `src/dns/server/mod.rs`

### 3.7 Update DNS QueryContext Line Reference
- **Source:** consolidated_review_plan.md:164
- **File:** `architecture/dns_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Update line 517 reference to 419-445 for QueryContext

---

## Theme 4: Post-Quantum / Layer 3.5 Security

### 4.1 Document BUG-L1 Fail-Safe Behavior
- **Source:** consolidated_review_plan.md:108 (layer_3_5_review_plan.md)
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Priority:** P1 (High)
- **Action:** Document `verify_hybrid()` returns `true` when signature lacks ML-DSA data (fail-safe)
- **Code Ref:** `src/mesh/ml_dsa.rs:206-218`

### 4.2 Document BUG-L3 ML-KEM Proof-of-Possession
- **Source:** consolidated_review_plan.md:121 (layer_3_5_review_plan.md)
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Priority:** P1 (High)
- **Action:** Document ML-KEM key exchange proof-of-possession at `confirm_key` method
- **Code Ref:** `src/mesh/ml_kem_key_exchange.rs:204-264`

### 4.3 Add Post-Quantum Provider Installation Details
- **Source:** consolidated_review_plan.md:127 (layer_3_5_review_plan.md)
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Document `rustls_post_quantum::provider()` installed at `src/startup/master.rs:210-234`
- **Reason:** Provides X25519MLKEM768 hybrid key exchange

### 4.4 Add MESH-15 Reference for Quorum Deadlock
- **Source:** consolidated_review_plan.md:133 (layer_3_5_review_plan.md)
- **File:** `architecture/layer_3_5_deep_dive.md`, Line 43
- **Priority:** P2 (Medium)
- **Action:** Add "See MESH-15" reference to quorum deadlock risk statement

### 4.5 Fix Naming Inconsistency
- **Source:** consolidated_review_plan.md:139 (layer_3_5_review_plan.md)
- **File:** `architecture/networking_deep_dive.md`, Line 68
- **Priority:** P3 (Low)
- **Action:** Change `X25519MLKEM768Draft00` to `X25519MLKEM768`

### 4.6 Add Async Verification Pool Documentation
- **Source:** consolidated_review_plan.md:145 (layer_3_5_review_plan.md)
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Document `verify_hybrid_async()` uses `CryptoVerificationPool`
- **Code Ref:** `src/mesh/protocol.rs:197-232`

---

## Theme 5: Code Reference Corrections (AGENTS.md + Architecture Docs)

### 5.1 Fix collect_body_with_chunk_waf Line Reference
- **Source:** consolidated_review_plan.md:155 (networking_review_plan.md)
- **File:** `AGENTS.md` Known File Path Corrections table
- **Priority:** P2 (Medium)
- **Action:** Change `src/http/server.rs:4532` → `src/http/server.rs:4662`

### 5.2 Add TunnelBackend to_backend() Line Reference
- **Source:** consolidated_review_plan.md:170 (layer_3_5_review_plan.md)
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Reference lines 120-122 for `TunnelBackend::to_backend()`
- **Code Ref:** `src/tunnel/upstream.rs:120-122`

### 5.3 WAF Plugin Execution Line Reference
- **Source:** plugin_review_plan.md:18
- **File:** `architecture/plugin_deep_dive.md:240`
- **Priority:** P2 (Medium)
- **Action:** Change `3043-3060` → `3050-3060` for WASM filter execution
- **Code Ref:** `src/http/server.rs:3050-3060`

### 5.4 SpinHttpHandler Line Reference
- **Source:** plugin_review_plan.md:82
- **File:** `architecture/plugin_deep_dive.md:117`
- **Priority:** P2 (Medium)
- **Action:** Change `2417-2489` → `2420-2503`
- **Code Ref:** `src/http/server.rs:2420-2503`

### 5.5 Spin find_route() Line Reference
- **Source:** plugin_review_plan.md:103
- **File:** `architecture/plugin_deep_dive.md:141`
- **Priority:** P2 (Medium)
- **Action:** Change `273-291` → `280-299`
- **Code Ref:** `src/spin/runtime.rs:280-299`

### 5.6 PatternDetector Line Reference (WAF)
- **Source:** waf_review_plan.md:17
- **File:** `architecture/waf_deep_dive.md:51`
- **Priority:** P3 (Low)
- **Action:** `264` → `293`
- **Code Ref:** `src/waf/attack_detection/detector_common.rs:293`

### 5.7 SO_REUSEPORT File Reference
- **Source:** process_lifecycle_review_plan.md:41
- **File:** `architecture/process_lifecycle.md:50`
- **Priority:** P2 (Medium)
- **Action:** Change `src/overseer/spawn.rs:43` → `src/startup/worker.rs:42`
- **Note:** Also reference `src/process/manager.rs:558-612`

### 5.8 PeakEwma Formula Line Reference
- **Source:** routing_review_plan.md:33
- **File:** `architecture/routing_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Change `src/upstream/pool.rs:48-57` → `src/upstream/pool.rs:513-528`
- **Reason:** Enum definition vs actual formula implementation

### 5.9 Quorum Verification Line Reference
- **Source:** mesh_review_plan.md:35
- **File:** `architecture/mesh_deep_dive.md`
- **Priority:** P1 (High)
- **Action:** Change `860-934` → `874-1092` for quorum verification functions
- **Code Ref:** `src/mesh/dht/signed.rs:874-1092`

---

## Theme 6: Undocumented Components

### 6.1 Document SocketOptionsBase
- **Source:** consolidated_review_plan.md:180 (networking_review_plan.md)
- **File:** `architecture/networking_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Add `SocketOptionsBase` to listener configuration section
- **Code Ref:** `src/listener/common.rs:4-18`

### 6.2 Add Listener Pool Auto-Tuning Detail
- **Source:** consolidated_review_plan.md:186 (worker_review_plan.md)
- **File:** `architecture/worker_architecture.md`
- **Priority:** P3 (Low)
- **Action:** Document `std::thread::available_parallelism()` mechanism

### 6.3 Add tokio::select! Diagram
- **Source:** consolidated_review_plan.md:192 (worker_review_plan.md)
- **File:** `architecture/worker_architecture.md`
- **Priority:** P3 (Low)
- **Action:** Consider adding diagram for listener management pattern
- **Code Ref:** `src/server/mod.rs:1066-1115`

### 6.4 Document MeshProxy Component
- **Source:** mesh_review_plan.md:17
- **File:** `architecture/mesh_deep_dive.md`
- **Priority:** P1 (High)
- **Action:** Add section documenting MeshProxy as central routing component
- **Code Ref:** `src/mesh/proxy.rs:63-78` (1994 lines)

### 6.5 Document Raft Implementation
- **Source:** mesh_review_plan.md:52
- **File:** `architecture/mesh_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Add section describing Raft module structure
- **Code Ref:** `src/mesh/raft/*.rs`

---

## Theme 7: Documentation Completeness

### 7.1 Add service/ Subdirectory to Platform Docs
- **Source:** platform_review_plan.md:82
- **File:** `architecture/platform_deep_dive.md:15-27`
- **Priority:** P2 (Medium)
- **Action:** Add `service/` (Windows service integration) to key files table

### 7.2 Add windows/ Subdirectory to Platform Docs
- **Source:** platform_review_plan.md:94
- **File:** `architecture/platform_deep_dive.md:15-27`
- **Priority:** P2 (Medium)
- **Action:** Add `windows/` (firewall, interface resolver, wintun) to key files table

### 7.3 Add Guest Alloc/Free Clarification to Plugin Docs
- **Source:** plugin_review_plan.md:58
- **File:** `architecture/plugin_deep_dive.md:109`
- **Priority:** P2 (Medium)
- **Action:** Clarify guest_alloc/guest_free are from module exports, not linker

### 7.4 Add WASM Execution Flow Enhancement
- **Source:** plugin_review_plan.md:208
- **File:** `architecture/plugin_deep_dive.md:241-246`
- **Priority:** P3 (Low)
- **Action:** Clarify per-site vs global plugin flow

### 7.5 Add Instance Pooling Diagram Clarification
- **Source:** plugin_review_plan.md:230
- **File:** `architecture/plugin_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Clarify pooled vs non-pooled execution flow

### 7.6 Document Connection Pool Lifecycle
- **Source:** routing_review_plan.md:44
- **File:** `architecture/routing_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Add reference to `src/upstream/pool.rs:545-580` for connection lifecycle

### 7.7 Document Health Monitoring Implementation
- **Source:** routing_review_plan.md:58
- **File:** `architecture/routing_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Add reference to `src/upstream/health.rs`

### 7.8 Add CGI Handler Documentation
- **Source:** app_handlers_review_plan.md:149
- **File:** `architecture/app_handlers.md`
- **Priority:** P2 (Medium)
- **Action:** Add section for CGI support (currently completely missing)

### 7.9 Add File Manager Documentation
- **Source:** app_handlers_review_plan.md:162
- **File:** `architecture/app_handlers.md`
- **Priority:** P3 (Low)
- **Action:** Document file upload, malware scanning, archive extraction

### 7.10 Add ConfigManager Test Suite Documentation
- **Source:** config_review_plan.md:96
- **File:** `architecture/config_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** Document test suite at `crates/synvoid-config/src/lib.rs:244-447`

### 7.11 Add Missing Config Files to Key Files Table
- **Source:** config_review_plan.md:113
- **File:** `architecture/config_deep_dive.md:27-44`
- **Priority:** P2 (Medium)
- **Action:** Add validation.rs, process.rs, protection.rs, bandwidth.rs, limits.rs, network.rs, traffic.rs, theme.rs

### 7.12 Fix macOS Seatbelt Sandbox Status
- **Source:** platform_review_plan.md:17
- **File:** `architecture/platform_deep_dive.md:373`
- **Priority:** P1 (High)
- **Action:** Change "planned but not yet implemented" to "implemented but disabled by default - requires `macos-sandbox` Cargo feature"
- **Code Ref:** `src/platform/sandbox.rs:1036-1044` (feature gate at line 1037, not 1022)
- **Verification:** `rg "macos-sandbox" Cargo.toml`

### 7.13 Add CPU Affinity Linux-Only Caveat
- **Source:** platform_review_plan.md:37
- **File:** `architecture/platform_deep_dive.md:261`
- **Priority:** P2 (Medium)
- **Action:** Add "(Linux-only)" note to CPU affinity diagram claim
- **Code Ref:** `src/worker/unified_server.rs:183-204`

### 7.14 Update Windows Sandbox Description (DEP + ASLR)
- **Source:** platform_review_plan.md:51
- **File:** `architecture/platform_deep_dive.md:64`
- **Priority:** P3 (Low)
- **Action:** Add DEP and ASLR mitigation policies

### 7.15 Clarify Postcard Choice Rationale
- **Source:** config_review_plan.md:128
- **File:** `architecture/config_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Clarify Postcard choice is canonical codebase standard

---

## Theme 8: Admin API Documentation Corrections

### 8.1 Remove "No CORS Middleware" Claim
- **Source:** admin_review_plan.md:80
- **File:** `architecture/admin_deep_dive.md:154-156`
- **Priority:** P1 (High)
- **Action:** CORS is fully implemented via `create_cors_layer()` - correct the claim

### 8.2 Remove "Legacy Overseer" Designation
- **Source:** admin_review_plan.md:67
- **File:** `architecture/admin_deep_dive.md:231`
- **Priority:** P1 (High)
- **Action:** Overseer endpoints are fully functional, not legacy

### 8.3 Update Handler Count
- **Source:** admin_review_plan.md:95
- **File:** `architecture/admin_deep_dive.md:179`
- **Priority:** P2 (Medium)
- **Action:** Change "26+" to "24 handlers + up to 4 mesh-gated handlers"

### 8.4 Add Swagger UI Feature Gate Documentation
- **Source:** admin_review_plan.md:174
- **File:** `architecture/admin_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Note `/api/docs` is feature-gated with `#[cfg(feature = "swagger-ui")]`

### 8.5 Update CSRF Validation Line Numbers
- **Source:** admin_review_plan.md:209
- **File:** `architecture/admin_deep_dive.md`
- **Priority:** P2 (Medium)
- **Action:** `validate_csrf()`: 725-741 → 728-749, `generate_csrf_token()`: 743-771 → 751-779
- **Action:** `create_session()`: 788-820 → 796-828, `validate_session()`: 822-844 → 830-849

---

## Theme 9: Code Quality Issues

### 9.1 Examine Duplicate collect_body_with_chunk_waf Implementations
- **Source:** consolidated_review_plan.md:202 (networking_review_plan.md)
- **Files:** `src/http/server.rs:4662`, `src/tls/server.rs:2078`
- **Priority:** P2 (Medium)
- **Action:** Examine whether implementations are duplicated or intentionally separate

### 9.2 SiteConnectionLimiter Ignores Max Limits
- **Source:** proxy_review_plan.md:125
- **Location:** `src/waf/traffic_shaper/limiter.rs:51-98`
- **Priority:** P2 (Medium)
- **Action:** `try_acquire_with_limits()` accepts max_per_site/max_per_ip but `try_acquire()` passes `None`
- **Bug ID:** Known Issue

### 9.3 Capsicum Sandbox limit_fd() Dead Code
- **Source:** platform_review_plan.md:142
- **Location:** `src/platform/sandbox.rs:516-528`
- **Priority:** P2 (Medium)
- **Action:** Either implement FD rights limiting or remove unused method

### 9.4 Clarify handle_request_with_cache in Proxy
- **Source:** consolidated_review_plan.md:208 (networking_review_plan.md)
- **File:** `architecture/networking_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Clarify proxy has separate method with same name but different signature

### 9.5 Fix BUG-ROUTER-1 Reference Misleading
- **Source:** routing_review_plan.md:22
- **File:** `architecture/routing_deep_dive.md`
- **Priority:** P3 (Low)
- **Action:** Remove or update BUG-ROUTER-1 reference - line 1318 doesn't match bug fix

### 9.6 Fix StaticFileHandler Location Reference
- **Source:** app_handlers_review_plan.md:26
- **File:** `architecture/app_handlers.md`
- **Priority:** P2 (Medium)
- **Action:** Change `src/static_files/handler.rs` → `src/static_files/mod.rs:42`

### 9.7 Granian Support Is REAL (NOT false)
- **Source:** app_handlers_review_plan.md:70
- **File:** `architecture/app_handlers.md`
- **Priority:** P0 (Critical - Documentation Error)
- **Action:** UPDATE documentation - Granian IS integrated. Extensive implementation exists at `src/app_server/granian.rs` (959 lines) with GranianSupervisor, GranianConfig, process management, auto-install, logging, and admin API endpoints. 62 references across the codebase. Do NOT remove - ADD COMPLETE documentation.
- **Verification:** `rg "granian" src/`

### 9.8 Clarify Spin Instance Pooling
- **Source:** app_handlers_review_plan.md:100
- **File:** `architecture/app_handlers.md`
- **Priority:** P2 (Medium)
- **Action:** Spin caches compiled runtimes but creates new instances per request

---

## Theme 10: Bug Fixes (Critical)

### 10.1 Fix DnsConfig.validate() Not Called
- **Source:** config_review_plan.md:65
- **Location:** `crates/synvoid-config/src/main_config.rs:181-209` and `crates/synvoid-config/src/dns/mod.rs:174-205`
- **Priority:** P0 (Critical - Bug Fix)
- **Action:** Call `self.dns.validate()` in `MainConfig::validate()` when DNS feature enabled. Currently only `self.dns.enabled` is checked (line 192-198), no `.validate()` call exists.
- **Bug ID:** Known Issue (AGENTS.md)
- **Verification:** `grep -n "validate" crates/synvoid-config/src/main_config.rs`

### 10.2 Process Lifecycle: Update Reachability Claims
- **Source:** process_lifecycle_review_plan.md:136
- **File:** `architecture/process_lifecycle.md:31-32`
- **Priority:** P1 (High)
- **Action:** Documentation says "no CLI flag exists" but `--master` flag IS functional - either disable or update docs
- **Code Ref:** `src/main.rs:35`

### 10.3 Update Process Hierarchy Documentation
- **Source:** process_lifecycle_review_plan.md:183
- **File:** `architecture/process_lifecycle.md:5-41`
- **Priority:** P2 (Medium)
- **Action:** Revise to reflect actual process flow: DEFAULT is `run_supervisor_mode` (not `run_overseer_mode`). The hierarchy is Supervisor → Master (--master flag) → Worker. `run_overseer_mode` exists but is NOT the default entry point. See `src/main.rs:538-547`.
- **Code Ref:** `src/main.rs:529-531` (master mode), `src/main.rs:538-547` (supervisor mode as default)

### 10.4 Clarify CPU Affinity Behavior
- **Source:** process_lifecycle_review_plan.md:228
- **File:** `architecture/process_lifecycle.md:51`
- **Priority:** P2 (Medium)
- **Action:** Remove "automatically assigned" - it's explicit via `--cpu-affinity` or Supervisor assignment

### 10.5 Document Worker Types Accurately
- **Source:** process_lifecycle_review_plan.md:253
- **File:** `architecture/process_lifecycle.md:45-47`
- **Priority:** P2 (Medium)
- **Action:** BaseWorkerProcess is NOT deprecated - clarify worker types

---

## Theme 11: Verification Items

### 11.1 Verify BufferPool Implementation
- **Source:** consolidated_review_plan.md:218
- **Action:** Confirm `crates/synvoid-utils/src/buffer/pool.rs` exists and matches documentation
- **Priority:** P2 (Medium)

### 11.2 Verify UDP Amplification Protection
- **Source:** consolidated_review_plan.md:223
- **Action:** Either remove "Built-in protections" claim or provide specific implementation details
- **Priority:** P3 (Low)

### 11.3 Verify HTTP/2 Connection Pooling Limitation
- **Source:** consolidated_review_plan.md:229
- **Action:** Determine if `is_http2 = true` hardcode at `src/http_client/mod.rs:893` is by design
- **Priority:** P2 (Medium)

### 11.4 Verify Message Enum Category Count
- **Source:** platform_review_plan.md:73
- **File:** `architecture/platform_deep_dive.md:94`
- **Action:** Recount Message enum variants at `src/process/ipc.rs`
- **Priority:** P3 (Low)

### 11.5 Verify BufferPool Location
- **Source:** waf_review_plan.md:134
- **Action:** Check if path `crates/synvoid-utils/src/buffer/pool.rs` has changed
- **Priority:** P3 (Low)

---

## Supervisor Migration (Longest Sequential Path - P0)

This is the critical path. All other items can be done in parallel before or after this work.

See detailed plan at: `plans/migration.md`

### Summary of Migration Waves

| Wave | Description | Duration | Dependencies |
|------|-------------|----------|---------------|
| 1 | Extract Health, Preflight, State from Overseer | Day 1 | None |
| 2 | Implement Rolling Restart | Days 2-3 | Wave 1 |
| 3 | Auto-Rollback + Recovery | Day 4 | Wave 2 |
| 4 | CLI Integration | Day 5 | Wave 2 |
| 5 | Remove Legacy Code (Overseer/Master) | Days 6-7 | Wave 3 |
| 6 | Integration Testing | Day 8 | Wave 5 |

**Net Result:** ~1500 lines removed overall, single Supervisor process mode

---

## Wave Execution Summary

### Waves 1-5: Can Execute in Parallel (Before Migration)

**Wave 1: P0-P1 Critical Fixes**
1. Theme 10.1: Fix DnsConfig.validate() not called
2. Theme 4.1: Document BUG-L1 fail-safe
3. Theme 4.2: Document BUG-L3 ML-KEM proof-of-possession
4. Theme 7.12: Fix macOS Seatbelt status
5. Theme 8.1: Remove "No CORS" claim
6. Theme 8.2: Remove "Legacy Overseer" designation
7. Theme 10.3: Update process hierarchy (default is supervisor, not overseer)
8. Theme 9.7: Granian IS integrated - ADD documentation (NOT remove)

**Wave 2: P1 Documentation Corrections**
1. Theme 3.1: Fix Cookie RFC reference
2. Theme 3.2: Remove DnsServerQueryHandler reference
3. Theme 3.3: Add DNSSEC limitations note
4. Theme 1.1: Fix HTTP/2 status in worker architecture
5. Theme 1.3: ErasedHttpClient Phase 9 incomplete
6. Theme 5.9: Quorum verification line numbers
7. Theme 6.4: Document MeshProxy component
8. Theme 9.2: SiteConnectionLimiter max limits

**Wave 3: P2 Medium Priority**
1. Theme 2.1: Correct WAF pipeline stage order
2. Theme 3.4: Document AXFR record type gaps
3. Theme 3.5: Add GOST DS digest note
4. Theme 4.3: Add post-quantum provider installation details
5. Theme 4.4: Add MESH-15 reference
6. Theme 5.1: Fix collect_body_with_chunk_waf line
7. Theme 5.3: WAF plugin execution line reference
8. Theme 5.4: SpinHttpHandler line reference
9. Theme 5.5: Spin find_route() line reference
10. Theme 5.7: SO_REUSEPORT file reference
11. Theme 5.8: PeakEwma formula line reference
12. Theme 6.4: Document Raft implementation
13. Theme 7.1: Add service/ subdirectory
14. Theme 7.2: Add windows/ subdirectory
15. Theme 7.3: Add guest_alloc/fre e clarification
16. Theme 7.6: Document connection pool lifecycle
17. Theme 7.7: Document health monitoring
18. Theme 7.8: Add CGI handler documentation
19. Theme 7.10: Add ConfigManager test suite docs
20. Theme 7.11: Add missing config files
21. Theme 8.3: Update handler count
22. Theme 8.5: Update CSRF validation line numbers
23. Theme 9.1: Examine duplicate collect_body impls
24. Theme 9.3: Capsicum limit_fd() dead code
25. Theme 10.2: Update process hierarchy docs
26. Theme 10.3: Clarify CPU affinity behavior
27. Theme 10.4: Document worker types

**Wave 4: P2-P3 Low Priority**
1. Theme 2.2: Clarify bot protection inline challenge
2. Theme 2.3: Document ChallengeWithCookie variant
3. Theme 2.4: PatternDetector line reference
4. Theme 3.6: Document cookie server integration
5. Theme 3.7: Update DNS QueryContext line reference
6. Theme 4.5: Fix naming inconsistency
7. Theme 4.6: Add async verification pool docs
8. Theme 5.2: TunnelBackend to_backend() line
9. Theme 5.6: Additional pattern detector reference
10. Theme 6.1: Document SocketOptionsBase
11. Theme 6.2: Add listener pool auto-tuning detail
12. Theme 6.3: Add tokio::select! diagram
13. Theme 7.4: Add WASM execution flow enhancement
14. Theme 7.5: Add instance pooling diagram
15. Theme 7.9: Add file manager documentation
16. Theme 7.13: Add CPU affinity Linux-only caveat
17. Theme 7.14: Update Windows sandbox description
18. Theme 7.15: Clarify Postcard choice rationale
19. Theme 8.4: Add Swagger UI feature gate
20. Theme 9.4: Clarify handle_request_with_cach e
21. Theme 9.5: Fix BUG-ROUTER-1 reference
22. Theme 9.6: Fix StaticFileHandler location
23. Theme 9.8: Clarify Spin instance pooling

**Wave 5: Verification Items**
1. Theme 11.1: Verify UDP amplification protection
2. Theme 11.2: Verify HTTP/2 connection pooling limitation
3. Theme 11.3: Verify Message enum category count
4. Theme 11.4: Verify BufferPool location
5. Theme 11.5: Verify BufferPool implementation

**Wave 6: Supervisor Migration (Sequential Critical Path)**
- Execute migration plan in order (Waves 1-6 from migration.md)
- All Waves 1-5 should be completed before Wave 5 (removal)

---

## Source Plan Attribution

| Source Plan | Items Contributed |
|-------------|------------------|
| `consolidated_review_plan.md` (Batch 1) | 22 items |
| `proxy_review_plan.md` (Batch 2) | 8 items |
| `admin_review_plan.md` (Batch 2) | 6 items |
| `plugin_review_plan.md` (Batch 2) | 6 items |
| `waf_review_plan.md` (Batch 2) | 7 items |
| `routing_review_plan.md` (Batch 3) | 4 items |
| `process_lifecycle_review_plan.md` (Batch 3) | 5 items |
| `platform_review_plan.md` (Batch 3) | 6 items |
| `mesh_review_plan.md` (Batch 3) | 4 items |
| `app_handlers_review_plan.md` (Batch 4) | 8 items |
| `config_review_plan.md` (Batch 4) | 5 items |
| `migration.md` (Batch 4) | 1 epic (6 waves) |

**Total Items:** ~70 action items consolidated into 8 themes + 1 epic migration

---

## Verification Commands

```bash
# Verify all profiles compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Verify compilation without errors
cargo check --lib --no-run
cargo test --lib --no-run

# Format and clippy
cargo fmt && cargo clippy --lib -- -D warnings

# Module-specific checks
cargo check --lib -p synvoid-plugin
cargo check --lib -p synvoid-spin
cargo check --lib -p synvoid-serverless

# Run tests
cargo test --lib
cargo test --test integration_test

# Verify no legacy references (after migration)
# grep -r "run_master_mode\|run_overseer_mode" src/  # Should return empty
# grep -r "overseer::" src/  # Should return empty
```

---

*Plan consolidated: 2026-05-26*
