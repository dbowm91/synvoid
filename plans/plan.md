# SynVoid Consolidated Action Plan

**Generated:** 2026-05-26
**Status:** PLANNED
**Last Updated:** 2026-05-26 (verification corrections applied)

---

## Executive Summary

This document consolidates all action items from four batches of architecture review plans. The items are organized into **5 parallel work waves** plus the **sequential Supervisor Migration** (the longest critical path). All waves 1-5 can execute in parallel and complete before or after migration; only the migration removal phase depends on prior wave completion.

| Category | Items | Priority |
|----------|-------|----------|
| Documentation Corrections | 35 | Mixed P1-P3 |
| Code Quality/Bugs | 12 | P0-P2 |
| Architecture Documentation | 15 | P1-P2 |
| Supervisor Migration | 1 epic (6 sub-waves) | P0 |

---

## How to Use This Plan

This plan is designed for parallel execution by multiple sub-agents. Each wave contains independent items that can be worked on concurrently. The Supervisor Migration is the critical path and must be executed sequentially after Waves 1-5 content is implemented.

**For future agents:** Each item includes the file path, line numbers, and specific action to take. Read the referenced source code before making changes to ensure you understand the context. Run `cargo check` after each file modification.

---

## Wave 1: P0-P1 Critical Fixes (Can Execute in Parallel)

### 1.1 [P0] Fix DnsConfig.validate() Not Called
- **File:** `crates/synvoid-config/src/main_config.rs:181-209`
- **Issue:** `self.dns.validate()` is never called in `MainConfig::validate()`. Only `self.dns.enabled` is checked at lines 192-198.
- **Action:** Add `self.dns.validate()` call in `MainConfig::validate()` when DNS feature is enabled. See `crates/synvoid-config/src/dns/mod.rs:174-205` for the validate() implementation.
- **Verification:** `grep -n "validate" crates/synvoid-config/src/main_config.rs`

### 1.2 [P1] Document BUG-L1 Fail-Safe Behavior
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Action:** Document that `verify_hybrid()` at `src/mesh/ml_dsa.rs:206-218` returns `true` when a signature lacks ML-DSA data. This is intentional fail-safe behavior.
- **Code:** When `signature.has_ml_dsa()` is false, the function returns `true` (treating as valid).
- **Why:** If PQC algorithm is broken or unavailable, fail-safe allows the system to operate on classical signatures alone.

### 1.3 [P1] Document BUG-L3 ML-KEM Proof-of-Possession
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Action:** Document ML-KEM key exchange proof-of-possession verification at `src/mesh/ml_kem_key_exchange.rs:204-264`.
- **Code:** The `confirm_key` method at line 241 verifies client public key matches stored session public key, then calls `MlKem768::decapsulate()` to confirm the client can actually use the shared secret.
- **Why:** This prevents a rogue server from successfully completing key exchange without the client being able to decapsulate.

### 1.4 [P1] Fix macOS Seatbelt Sandbox Status
- **File:** `architecture/platform_deep_dive.md:373`
- **Action:** Change "planned but not yet implemented" to "implemented but disabled by default - requires `macos-sandbox` Cargo feature"
- **Code:** `src/platform/sandbox.rs:1036-1044` - `SeatbeltSandbox::is_supported()` exists. Feature gate is at line 1037: `#[cfg(feature = "macos-sandbox")]`
- **Verification:** `rg "macos-sandbox" Cargo.toml`

### 1.5 [P1] Remove "No CORS Middleware" Claim
- **File:** `architecture/admin_deep_dive.md:154-156`
- **Action:** CORS is fully implemented via `create_cors_layer()` at `src/admin/mod.rs:50-97`. Remove any claim that CORS is missing.
- **Code:** The CORS layer is created and added to the router in the admin API setup.

### 1.6 [P1] Remove "Legacy Overseer" Designation
- **File:** `architecture/admin_deep_dive.md:231`
- **Action:** Overseer endpoints are fully functional at multiple locations in the codebase:
  - `src/admin/mod.rs:242, 607`
  - `src/admin/handlers/config.rs:582-645`
  - `src/admin/handlers/system.rs:566`
- **Clarification:** The overseer code is legacy from an architecture perspective (will be removed in migration), but the admin API endpoints themselves are functional and used.

### 1.7 [P1] Update Process Hierarchy (Default is Supervisor)
- **File:** `architecture/process_lifecycle.md:5-41`
- **Action:** Revise to reflect actual process flow:
  - DEFAULT is `run_supervisor_mode` (lines 538-547 in main.rs)
  - `--master` flag goes to `run_master_mode` (line 529)
  - `run_overseer_mode` exists but is NOT the default entry point
- **Key Point:** Documentation currently implies overseer is the primary mode - it should say supervisor is the default.

### 1.8 [P0] Granian IS Integrated - ADD Documentation (NOT Remove)
- **File:** `architecture/app_handlers.md`
- **Action:** This is a CRITICAL documentation error. Granian IS fully integrated with extensive implementation at `src/app_server/granian.rs` (1047 lines).
- **Evidence:**
  - `GranianSupervisor` struct with full process management
  - `GranianConfig` for configuration
  - Auto-install support
  - Admin API endpoints
  - 70+ references across the codebase
- **Do NOT:** Remove or downplay Granian support
- **Do:** Add complete documentation of Granian integration
- **Verification:** `rg "granian" src/` returns 70+ matches

---

## Wave 2: P1 Documentation Corrections (Can Execute in Parallel)

### 2.1 [P1] Fix Cookie RFC Reference
- **File:** `architecture/dns_deep_dive.md`, Line 39
- **Action:** Change RFC 8905 to RFC 8905/RFC 7873 - cookies via EDNS option
- **Reason:** Code at `src/dns/cookie.rs:47-48` cites RFC 7873. RFC 8905 is "The DNS Cookie AD RR" (EDNS option), RFC 7873 is "Domain Names over (TLS) Transport" (cookies for DoT).

### 2.2 [P1] Remove DnsServerQueryHandler Reference
- **File:** `architecture/dns_deep_dive.md`, Line 69
- **Action:** Change `DnsServerQueryHandler` to `QueryContext` - this struct does not exist
- **Actual:** `QueryContext` at `src/dns/server/mod.rs:419-445`

### 2.3 [P1] Add DNSSEC Limitations Note
- **File:** `architecture/dns_deep_dive.md`
- **Action:** Add note about manual wire format construction and lacking compression support
- **Code:** `src/dns/dnssec.rs:1-13` - Module doc explicitly states these limitations.

### 2.4 [P1] Fix HTTP/2 Status in Worker Architecture
- **File:** `architecture/worker_architecture.md`, Line 13
- **Action:** Change "Currently disabled (`is_http2 = false`)" to "Enabled via ALPN negotiation"
- **Reason:** Server-side HTTP/2 negotiation at `src/tls/server.rs:411-487` uses ALPN: `let is_http2 = alpn_protocol.map(|p| p == ALPN_HTTP2).unwrap_or(false);`
- **Note:** This is separate from the upstream hardcoded `is_http2 = true` at `src/http_client/mod.rs:893`.

### 2.5 [P1] ErasedHttpClient Phase 9 Incomplete
- **Location:** `src/http/server.rs:3305`
- **Action:** Change `use_erased_client = false` hardcoded to conditional logic based on streaming body detection
- **Bug ID:** Known Issue - ErasedHttpClient is infrastructure ready but never used
- **Verification:** `cargo check --features mesh,dns`

### 2.6 [P1] Quorum Verification Line Reference
- **File:** `architecture/mesh_deep_dive.md`
- **Action:** Change `860-934` → `874-1092` for quorum verification functions
- **Code:** `src/mesh/dht/signed.rs:874` starts `verify_quorum_proof`, line 963 is `verify_quorum_proof_with_context`, line 1082 is `verify_quorum_proof_minimum_threshold`
- **Also Update:** AGENTS.md Known File Path Corrections table entry for this location

### 2.7 [P1] Document MeshProxy Component
- **File:** `architecture/mesh_deep_dive.md`
- **Action:** Add section documenting MeshProxy as central routing component
- **Code:** `src/mesh/proxy.rs:63-78` (1994 lines total)
- **Key:** MeshProxy is not mentioned in the module overview but is a critical routing component

### 2.8 [P2] SiteConnectionLimiter Max Limits Not Enforced
- **Location:** `src/waf/traffic_shaper/limiter.rs:51-98`
- **Action:** `try_acquire_with_limits()` accepts max_per_site/max_per_ip but `try_acquire()` at line 42 passes `None` for these values
- **Bug ID:** Known Issue
- **Impact:** Connection limits configured via `max_connections_per_site` and `max_connections_per_ip` are ignored

---

## Wave 3: P2 Medium Priority (Can Execute in Parallel)

### 3.1 [P2] Correct WAF Pipeline Stage Order
- **File:** `architecture/worker_architecture.md`, Lines 29-35
- **Action:** Swap stages 6 and 7:
  - **Current (WRONG):** 6. Attack Detection, 7. Flood Protection
  - **Correct Order:** 6. Flood Protection, 7. Attack Detection
- **Reason:** Code at `src/waf/mod.rs:476-514` shows flood check (476-484) runs BEFORE attack detection (486-514).

### 3.2 [P2] Document AXFR Record Type Coverage Gaps
- **File:** `architecture/dns_deep_dive.md`
- **Action:** Document missing record types in AXFR: NAPTR (35), CERT (37), SMMEA (48), DNAME (39)
- **Code:** `src/dns/transfer.rs:829-1029` handles A, AAAA, CNAME, NS, SOA, TXT, MX, SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA. Missing types fall through with `_ => continue`.
- **Note:** The match ends at line 1029 with `_ => continue`

### 3.3 [P2] Add GOST DS Digest Note
- **File:** `architecture/dns_deep_dive.md`
- **Action:** Note GOST DS digest (type 3) not supported
- **Code:** `src/dns/dnssec_validation.rs:260` returns error for digest type 3

### 3.4 [P2] Add Post-Quantum Provider Installation Details
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Action:** Document `rustls_post_quantum::provider()` installed at `src/startup/master.rs:210-234`
- **Reason:** Provides X25519MLKEM768 hybrid key exchange when `post-quantum` feature is enabled

### 3.5 [P2] Add MESH-15 Reference for Quorum Deadlock
- **File:** `architecture/layer_3_5_deep_dive.md`, Line 43
- **Action:** Add "See MESH-15" reference to quorum deadlock risk statement
- **MESH-15:** Quorum Deadlock Risk During Partition - Raft implementation incomplete, requires Raft migration

### 3.6 [P2] Fix collect_body_with_chunk_waf Line Reference
- **File:** `AGENTS.md` Known File Path Corrections table, and `architecture/networking_deep_dive.md`
- **Action:** Change `src/http/server.rs:4532` → `src/http/server.rs:4662`
- **Also Update:** The function definition is at line 4662

### 3.7 [P2] WAF Plugin Execution Line Reference
- **File:** `architecture/plugin_deep_dive.md:240`
- **Action:** Change `3043-3060` → `3050-3060` for WASM filter execution
- **Code:** `src/http/server.rs:3050-3060`

### 3.8 [P2] SpinHttpHandler Line Reference
- **File:** `architecture/plugin_deep_dive.md:117`
- **Action:** Change `2417-2489` → `2420-2503`
- **Code:** `src/http/server.rs:2420-2503`

### 3.9 [P2] Spin find_route() Line Reference
- **File:** `architecture/plugin_deep_dive.md:141`
- **Action:** Change `273-291` → `280-299`
- **Code:** `src/spin/runtime.rs:280-299`

### 3.10 [P2] SO_REUSEPORT File Reference
- **File:** `architecture/process_lifecycle.md:50`
- **Action:** Change `src/overseer/spawn.rs:43` → `src/startup/worker.rs:42`
- **Also:** Reference `src/process/manager.rs:558-612`

### 3.11 [P2] PeakEwma Formula Line Reference
- **File:** `architecture/routing_deep_dive.md`
- **Action:** Change `src/upstream/pool.rs:48-57` → `src/upstream/pool.rs:513-528`
- **Reason:** Enum definition is at 48-57, actual formula implementation is at 513-528

### 3.12 [P2] Document Raft Implementation
- **File:** `architecture/mesh_deep_dive.md`
- **Action:** Add section describing Raft module structure
- **Code:** `src/mesh/raft/*.rs`

### 3.13 [P2] Add service/ Subdirectory to Platform Docs
- **File:** `architecture/platform_deep_dive.md:15-27`
- **Action:** Add `service/` (Windows service integration) to key files table

### 3.14 [P2] Add windows/ Subdirectory to Platform Docs
- **File:** `architecture/platform_deep_dive.md:15-27`
- **Action:** Add `windows/` (firewall, interface resolver, wintun) to key files table

### 3.15 [P2] Add Guest Alloc/Free Clarification to Plugin Docs
- **File:** `architecture/plugin_deep_dive.md:109`
- **Action:** Clarify guest_alloc/guest_free are from module exports, not linker

### 3.16 [P2] Document Connection Pool Lifecycle
- **File:** `architecture/routing_deep_dive.md`
- **Action:** Add reference to `src/upstream/pool.rs:545-580` for connection lifecycle

### 3.17 [P2] Document Health Monitoring Implementation
- **File:** `architecture/routing_deep_dive.md`
- **Action:** Add reference to `src/upstream/health.rs`

### 3.18 [P2] Add CGI Handler Documentation
- **File:** `architecture/app_handlers.md`
- **Action:** Add section for CGI support (currently completely missing)
- **Code:** `src/cgi/mod.rs` (483 lines) exists but undocumented

### 3.19 [P2] Add ConfigManager Test Suite Documentation
- **File:** `architecture/config_deep_dive.md`
- **Action:** Document test suite at `crates/synvoid-config/src/lib.rs:244-447`

### 3.20 [P2] Add Missing Config Files to Key Files Table
- **File:** `architecture/config_deep_dive.md:27-44`
- **Action:** Add: validation.rs, process.rs, protection.rs, bandwidth.rs, limits.rs, network.rs, traffic.rs, theme.rs

### 3.21 [P2] Update Admin Handler Count
- **File:** `architecture/admin_deep_dive.md:179`
- **Action:** Change "26+" to reflect actual count. Based on `src/admin/handlers/mod.rs`:
  - Without mesh feature: 21 handlers
  - With mesh feature: 25 handlers (21 always + 4 mesh-gated: behavioral_intel, mesh_admin, mesh_topology, yara_rules)
- **Note:** The original plan said 24+4=28, but actual count is 21+4=25. Verify by running `rg "pub mod" src/admin/handlers/mod.rs`

### 3.22 [P2] Update CSRF Validation Line Numbers
- **File:** `architecture/admin_deep_dive.md`
- **Action:** Update line numbers:
  - `validate_csrf()`: 725-741 → 728-749
  - `generate_csrf_token()`: 743-771 → 751-779
  - `create_session()`: 788-820 → 796-828
  - `validate_session()`: 822-844 → 830-849

### 3.23 [P2] Examine Duplicate collect_body Implementations
- **Files:** `src/http/server.rs:4662`, `src/tls/server.rs:2078`
- **Action:** Examine whether `collect_body_with_chunk_waf` implementations in http/server.rs and tls/server.rs are duplicated or intentionally separate
- **Note:** Both have nearly identical implementations

### 3.24 [P2] Capsicum Sandbox limit_fd() Dead Code
- **Location:** `src/platform/sandbox.rs:516-528`
- **Action:** Either implement FD rights limiting or remove unused method
- **Issue:** Method defined but never called in `apply()` - FD rights limiting not active

### 3.25 [P2] Update Process Hierarchy Reachability Claims
- **File:** `architecture/process_lifecycle.md:31-32`
- **Action:** Documentation says "no CLI flag exists" but `--master` flag IS functional
- **Code:** `src/main.rs:35` - `master: bool` flag exists

### 3.26 [P2] Clarify CPU Affinity Behavior
- **File:** `architecture/process_lifecycle.md:51`
- **Action:** Remove "automatically assigned" - CPU affinity is explicit via `--cpu-affinity` or Supervisor assignment
- **Code:** `src/worker/unified_server.rs:183-204`

### 3.27 [P2] Document Worker Types Accurately
- **File:** `architecture/process_lifecycle.md:45-47`
- **Action:** BaseWorkerProcess is NOT deprecated - clarify worker types
- **Note:** BaseWorkerProcess handles raw TCP/UDP proxy, separate from HTTP workers

---

## Wave 4: P3 Low Priority (Can Execute in Parallel)

### 4.1 [P3] Clarify Bot Protection Inline Challenge
- **File:** `architecture/worker_architecture.md`
- **Action:** Clarify challenges come from `challenge_manager.generate_challenge_page()` within `check_bot_protection()`, not as separate stage
- **Code:** `src/waf/mod.rs:634-693`

### 4.2 [P3] Document ChallengeWithCookie Variant
- **File:** `architecture/waf_deep_dive.md`
- **Action:** Add `ChallengeWithCookie` to decision types documentation
- **Code:** `src/waf/mod.rs:67-73`

### 4.3 [P3] PatternDetector Line Reference Correction
- **File:** `architecture/waf_deep_dive.md:51`
- **Action:** Change `src/waf/attack_detection/detector_common.rs:264` → `src/waf/attack_detection/detector_common.rs:293`
- **Reason:** Line 264 is blank/closing brace. PatternDetector trait definition starts at line 293.

### 4.4 [P3] Document Cookie Server Integration Status
- **File:** `architecture/dns_deep_dive.md`
- **Action:** Clarify `cookie_server` field exists and is cloned in `DnsServer::clone()` at `src/dns/server/mod.rs:530`
- **Note:** The field IS cloned (not set to None as previously stated). The implementation exists at `src/dns/cookie.rs` but needs verification if fully wired into query flow.
- **Correction:** Previous plan said it was set to None - this was incorrect. It is cloned.

### 4.5 [P3] Update DNS QueryContext Line Reference
- **File:** `architecture/dns_deep_dive.md:517`
- **Action:** Update line 517 reference to 419-445 for QueryContext
- **Code:** `src/dns/server/mod.rs:419-445`

### 4.6 [P3] Fix Naming Inconsistency
- **File:** `architecture/networking_deep_dive.md`, Line 68
- **Action:** Change `X25519MLKEM768Draft00` to `X25519MLKEM768`
- **Reason:** Code uses final RFC 9420 name, not draft name

### 4.7 [P3] Add Async Verification Pool Documentation
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Action:** Document `verify_hybrid_async()` uses `CryptoVerificationPool`
- **Code:** `src/mesh/protocol.rs:197-232`

### 4.8 [P3] TunnelBackend to_backend() Line Reference
- **File:** `architecture/layer_3_5_deep_dive.md`
- **Action:** Reference lines 120-122 for `TunnelBackend::to_backend()`
- **Code:** `src/tunnel/upstream.rs:120-122`

### 4.9 [P3] Document SocketOptionsBase
- **File:** `architecture/networking_deep_dive.md`
- **Action:** Add `SocketOptionsBase` to listener configuration section
- **Code:** `src/listener/common.rs:4-18`

### 4.10 [P3] Add Listener Pool Auto-Tuning Detail
- **File:** `architecture/worker_architecture.md`
- **Action:** Document `std::thread::available_parallelism()` mechanism

### 4.11 [P3] Add tokio::select! Diagram
- **File:** `architecture/worker_architecture.md`
- **Action:** Consider adding diagram for listener management pattern
- **Code:** `src/server/mod.rs:1066-1115`

### 4.12 [P3] Add WASM Execution Flow Enhancement
- **File:** `architecture/plugin_deep_dive.md:241-246`
- **Action:** Clarify per-site vs global plugin flow

### 4.13 [P3] Add Instance Pooling Diagram Clarification
- **File:** `architecture/plugin_deep_dive.md`
- **Action:** Clarify pooled vs non-pooled execution flow

### 4.14 [P3] Add File Manager Documentation
- **File:** `architecture/app_handlers.md`
- **Action:** Document file upload, malware scanning, archive extraction
- **Code:** `src/static_files/file_manager.rs` exists but undocumented

### 4.15 [P3] Add CPU Affinity Linux-Only Caveat
- **File:** `architecture/platform_deep_dive.md:261`
- **Action:** Add "(Linux-only)" note to CPU affinity claim
- **Code:** `src/worker/unified_server.rs:183-204` logs warning on non-Linux platforms

### 4.16 [P3] Update Windows Sandbox Description
- **File:** `architecture/platform_deep_dive.md:64`
- **Action:** Add DEP and ASLR mitigation policies

### 4.17 [P3] Clarify Postcard Choice Rationale
- **File:** `architecture/config_deep_dive.md`
- **Action:** Clarify Postcard choice is canonical codebase standard for serialization

### 4.18 [P3] Add Swagger UI Feature Gate Documentation
- **File:** `architecture/admin_deep_dive.md`
- **Action:** Note `/api/docs` is feature-gated with `#[cfg(feature = "swagger-ui")]`

### 4.19 [P3] Clarify handle_request_with_cache in Proxy
- **File:** `architecture/networking_deep_dive.md`
- **Action:** Clarify proxy has separate method with same name but different signature
- **Code:** `src/tls/server.rs:606` vs `src/proxy/mod.rs:608`

### 4.20 [P3] Fix BUG-ROUTER-1 Reference
- **File:** `architecture/routing_deep_dive.md`
- **Action:** Remove or update BUG-ROUTER-1 reference - bug fix may have moved or the line reference is stale
- **Note:** BUG-ROUTER-1 was about hardcoded port 80 at `src/router.rs:1318` - this was fixed

### 4.21 [P3] Fix StaticFileHandler Location Reference
- **File:** `architecture/app_handlers.md`
- **Action:** Change `src/static_files/handler.rs` → `src/static_files/mod.rs:42`

### 4.22 [P3] Clarify Spin Instance Pooling
- **File:** `architecture/app_handlers.md`
- **Action:** Spin caches compiled runtimes but creates new instances per request

### 4.23 [P3] HTTP/2 Connection Pooling Non-Functional
- **Location:** `src/http_client/erased_pool.rs:204-206`
- **Action:** `Http2PooledConnection::is_available()` always returns `false`. Document as stub or implement.
- **Impact:** Only HTTP/1.1 used for upstream connections despite HTTP/2 infrastructure existing.

---

## Wave 5: Verification Items (Can Execute in Parallel)

These items require code investigation to determine if issues are by design or need fixing.

### 5.1 [P2] Verify BufferPool Implementation
- **Action:** Confirm `crates/synvoid-utils/src/buffer/pool.rs` exists and `BufferPool` implementation matches documentation
- **Verification:** Check file exists and read implementation

### 5.2 [P3] Verify UDP Amplification Protection
- **File:** `architecture/networking_deep_dive.md:23`
- **Action:** Either remove "Built-in protections against amplification attacks" claim or provide specific implementation details
- **Verification:** Search for amplification protection implementation

### 5.3 [P2] Verify HTTP/2 Connection Pooling Limitation
- **Location:** `src/http_client/mod.rs:893`
- **Action:** Determine if `is_http2 = true` hardcode is by design or can be fixed
- **Note:** Infrastructure supports HTTP/2 via `http2_only(false)` but hardcoded `true` bypasses dynamic detection

### 5.4 [P3] Verify Message Enum Category Count
- **File:** `architecture/platform_deep_dive.md:94`
- **Action:** Recount Message enum variants at `src/process/ipc.rs`
- **Verification:** Count actual variants and update if different

### 5.5 [P3] Verify BufferPool Location
- **Action:** Check if path `crates/synvoid-utils/src/buffer/pool.rs` has changed
- **Verification:** `ls -la crates/synvoid-utils/src/buffer/`

---

## Supervisor Migration (Critical Path - Sequential)

The migration consolidates Overseer/Master into a single Supervisor process. This is the longest critical path and must be executed sequentially.

**See detailed migration plan at:** `plans/migration.md`

### Migration Summary

The migration removes legacy code and implements zero-downtime upgrades:

| Phase | Description | Duration |
|-------|-------------|----------|
| Wave 1 | Extract Health, Preflight, State from Overseer | Day 1 |
| Wave 2 | Implement Rolling Restart | Days 2-3 |
| Wave 3 | Auto-Rollback + Recovery | Day 4 |
| Wave 4 | CLI Integration | Day 5 |
| Wave 5 | Remove Legacy Code (Overseer/Master) | Days 6-7 |
| Wave 6 | Integration Testing | Day 8 |

**Net Result:** ~1500 lines removed overall, single Supervisor process mode

### Critical Dependencies

1. Migration Waves 1-5 (extraction and implementation) can proceed independently
2. Migration Wave 5 (removal) MUST happen after all other plan items are complete
3. All other plan items (Waves 1-5 above) can be implemented in parallel with migration waves

### What Gets Removed

| File/Module | Lines | Reason |
|-------------|-------|--------|
| `src/startup/master.rs` | ~1031 | Functionality migrated to supervisor |
| `src/overseer/` module | ~8538 total | Unused legacy code |
| `src/startup/mod.rs` MasterState | ~100 | Replaced by SupervisorState |
| `--master` CLI flag | N/A | Legacy entry point |

### What Gets Added

| File | Lines | Purpose |
|------|-------|---------|
| `src/supervisor/health.rs` | ~600 | Health checking (from overseer) |
| `src/supervisor/preflight.rs` | ~250 | Preflight validation (from overseer) |
| `src/supervisor/upgrade_state.rs` | ~100 | Simplified state machine |
| `src/supervisor/upgrade.rs` | ~400 | Upgrade orchestrator |
| `tests/upgrade_test.rs` | ~400 | Integration tests |

---

## Verification Commands

After making changes, verify with these commands:

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

## Corrections Applied During Verification

The following items were corrected based on source file verification:

| Item | Original | Corrected | Source |
|------|----------|-----------|--------|
| Granian line count | 959 | 1047 | `wc -l src/app_server/granian.rs` |
| AXFR transfer range | 829-1019 | 829-1029 | `src/dns/transfer.rs:1029` match end |
| collect_body line | 4532 | 4662 | `src/http/server.rs:4662` |
| Quorum verify range | 860-934 | 874-1092 | `src/mesh/dht/signed.rs:874-1092` |
| Cookie server | Set to None | Cloned | `src/dns/server/mod.rs:530` |
| Handler count | 24+4=28 | 21+4=25 | `src/admin/handlers/mod.rs` count |

---

*Plan consolidated and verified: 2026-05-26*
