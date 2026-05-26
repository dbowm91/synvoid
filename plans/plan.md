# SynVoid Architecture Review - Consolidated Implementation Plan

**Generated:** 2026-05-26
**Last Updated:** 2026-05-26
**Status:** IN PROGRESS

---

## Executive Summary

This plan consolidates findings from architecture reviews across all SynVoid modules. Items are organized into waves based on dependency analysis to enable parallel implementation where possible.

### Wave Structure

| Wave | Focus | Parallelizable Items |
|------|-------|---------------------|
| Wave 1 | Critical Security & Line Reference Fixes | 3 items (all independent) |
| Wave 2 | Module-Specific Documentation Fixes | 6 items (3 pairs can run in parallel) |
| Wave 3 | Security Improvements | 4 items (mostly independent) |
| Wave 4 | Configuration & Routing Updates | 5 items (independent) |
| Wave 5 | DNSSEC & DNS Improvements | 5 items (independent) |

---

## Wave 1: Critical Security & Line Reference Fixes

**Priority: HIGH | All items are independent and can run in parallel**

### 1.1 Fix CSRF Function Line References
- **File:** `src/admin/state.rs`
- **Issue:** Line references are stale; function names were misidentified
- **Action:**
  - Update `validate_csrf()` line reference from `725-741` to `728`
  - Update `generate_csrf_token()` line reference from `743-771` to `751`
- **Note:** Functions are `validate_csrf` and `generate_csrf_token`, not `verify`/`generate`
- **Verification:** `rg "fn validate_csrf|fn generate_csrf_token" src/admin/state.rs`

### 1.2 Fix Session Function Line References
- **File:** `src/admin/state.rs`
- **Issue:** Line references are stale; `refresh` function doesn't exist
- **Action:**
  - Update `validate_session()` line reference from `788-820` to `830`
  - Add note: Session management uses `create_session`, `validate_session`, `invalidate_session`, `cleanup_expired_sessions` (no `refresh`)
- **Note:** `refresh` doesn't exist - use `validate_session` to check and potentially extend
- **Verification:** `rg "fn validate_session|fn create_session|fn invalidate_session" src/admin/state.rs`

### 1.3 Fix Message Category Count (Platform)
- **File:** `src/process/ipc.rs` or referenced documentation
- **Issue:** Document says "17 categories" but should be 18
- **Action:** Update count from 17 to 18 at line 94
- **Verification:** Count actual Message enum variants

---

## Wave 2: Module-Specific Documentation Fixes

**Priority: MEDIUM | Items are grouped by module for parallel execution**

### 2.1 Admin Module Fixes

#### 2.1.1 Clarify SecurityState Location
- **File:** `src/admin/state.rs:211-217`
- **Action:** Add explicit line reference comment in documentation
- **Verification:** `rg "SecurityState" src/admin/state.rs`

#### 2.1.2 Fix Handler Count
- **File:** Documentation referencing handlers
- **Issue:** Claims "26+" handlers but actual is 25 (20 always-on + 5 mesh-gated)
- **Action:** Update "26+" to "25 handlers" or clarify mesh-gated inclusion
- **Verification:** Count actual handler implementations

#### 2.1.3 Overseer → Supervisor Clarification
- **Files:** `src/admin/handlers/config.rs`, `src/admin/handlers/system.rs`, `src/admin/api/openapi.rs`
- **Issue:** Both Overseer and Supervisor API handlers coexist
- **Action:** Clarify that Overseer handlers (`OverseerConfigResponse`, `UpdateOverseerConfigRequest`, `OverseerStatusResponse`) are retained for backward compatibility during migration; new code should use Supervisor equivalents
- **Note:** Supervisor handlers (`SupervisorConfigResponse`, `UpdateSupervisorConfigRequest`, `SupervisorStatusResponse`) also exist at `src/admin/handlers/config.rs:767-811`
- **Verification:** `rg "OverseerConfigResponse|UpdateOverseerConfigRequest" src/admin/`

### 2.2 WAF Module Fixes

#### 2.2.1 PatternDetector Trait Line Reference
- **File:** `src/waf/attack_detection/detector_common.rs` (NOT `src/waf/detector_common.rs`)
- **Action:** Change line reference from `264` to `293`
- **Verification:** `rg "trait PatternDetector" src/waf/`

#### 2.2.2 SiteConnectionLimiter Line Reference
- **File:** `src/waf/traffic_shaper/limiter.rs:306`
- **Issue:** Struct is at line 306, not near description (lines 20-24)
- **Action:** Add explicit struct line reference in documentation
- **Verification:** `rg "struct SiteConnectionLimiter" src/waf/`

#### 2.2.3 Add Traffic Shaper Paths
- **Files:**
  - `src/waf/traffic_shaper/global.rs:10,182`
  - `src/waf/traffic_shaper/async_bucket.rs`
- **Action:** Document `GlobalTrafficShaper` and `SiteTrafficShaper` paths
- **Verification:** `ls src/waf/traffic_shaper/`

### 2.3 Platform Module Fixes

#### 2.3.1 Update Seatbelt Status
- **File:** `src/platform/sandbox.rs:1037-1044`
- **Issue:** Document says "planned, not yet implemented"
- **Action:** Change to "implemented via `macos-sandbox` feature flag"
- **Verification:** `rg "seatbelt|macos.sandbox" src/platform/`

#### 2.3.2 Add WorkerProcessBase Trait Note
- **File:** `src/process/worker.rs:11`
- **Action:** Document the trait that all worker types implement
- **Verification:** `rg "trait WorkerProcessBase" src/process/`

#### 2.3.3 Add peer_pid() Stub Note
- **File:** `src/platform/ipc.rs` or `src/process/ipc.rs`
- **Action:** Document that `IpcStream::peer_pid()` returns `None` - PID auth not used (HMAC used instead)
- **Verification:** `rg "fn peer_pid" src/`

### 2.4 Layer 3.5 Module Fixes

#### 2.4.1 Update PQC Dependency Reference
- **Issue:** Document says "Uses `libcrux`"
- **Action:** Change to "Uses the `pqc` crate (which wraps `libcrux-ml-dsa`)"
- **Verification:** `rg "pqc|libcrux" src/mesh/`

#### 2.4.2 Clarify TunnelBackend Path Reference
- **File:** `src/tunnel/upstream.rs:105`
- **Action:** Document TunnelBackend at `src/tunnel/upstream.rs:105` (NOT in router.rs - router has `TunnelRouter` instead)
- **Note:** `src/tunnel/router.rs` has `TunnelRouter` struct, not `TunnelBackend`
- **Verification:** `rg "struct TunnelBackend|struct TunnelRouter" src/tunnel/`

---

## Wave 3: Security Improvements

**Priority: HIGH | These address security concerns**

### 3.1 PoW Public Key Verification (Layer 3.5)
- **File:** `src/mesh/peer_auth.rs:540-604`
- **Status:** Already verified - `validate_edge_node_pow` at lines 590-595 already checks `pow_public_key == peer_public_key`
- **No action needed** - verification exists at lines 590-595:
  ```rust
  if pk_bytes != pow_pk_bytes {
      return Err(format!(
          "Edge node {} PoW public key does not match identity public key",
          peer_node_id
      ));
  }
  ```
- **Verification:** `rg "PoW public key does not match" src/mesh/`

### 3.2 NSEC3 Algorithm Fallback Logging (DNS)
- **File:** `src/dns/dnssec_signing.rs:203-211`
- **Status:** Already implemented - `tracing::warn!` logs when NSEC3 falls back to SHA-1:
  ```rust
  tracing::warn!(
      "Unsupported NSEC3 algorithm {}, falling back to SHA-1",
      config.algorithm
  );
  ```
- **No action needed**
- **Verification:** `rg "falling back to SHA-1" src/dns/dnssec_signing.rs`

### 3.3 Clarify HTTP/2 Status (Networking)
- **File:** `src/http_client/mod.rs:893`
- **Issue:** "not fully available" is vague
- **Action:**
  - Replace with specific: Infrastructure exists via `is_http2=true`
  - `.http2_only(false)` allows HTTP/1.1 fallback
  - Document what specifically is missing (if anything)
- **Verification:** `rg "is_http2|http2_only" src/http_client/`

### 3.4 UDP Amplification Protection Status (Networking)
- **File:** `src/udp/` (or wherever implemented)
- **Issue:** Document claims UDP amplification protection but no implementation found
- **Action:** Either add implementation or remove claim from documentation
- **Verification:** `rg "amplification|udp" src/udp/`

---

## Wave 4: Configuration & Routing Updates

**Priority: MEDIUM | Documentation consistency**

### 4.1 Config Module Fixes

#### 4.1.1 Update Main Config Hierarchy Table
- **File:** `crates/synvoid-config/src/` or architecture docs
- **Action:** Add missing fields: `mimes`, `asn_scraping`, `icmp_filter`, `honeypot_port` at correct line positions
- **Verification:** `rg "struct.*Config" crates/synvoid-config/src/`

#### 4.1.2 Update Site Config Hierarchy Table
- **File:** `crates/synvoid-config/src/` or architecture docs
- **Action:** Add missing fields: `blocked`, `whitelist`, `worker_pool`, `logging`, `tcp`, `udp`, `serverless`, `serverless_only`, `image_poison`
- **Verification:** `rg "SiteConfig|struct Site" crates/synvoid-config/src/`

#### 4.1.3 Document DnsConfig.validate() Limitation
- **File:** `crates/synvoid-config/src/dns/mod.rs:175-205`
- **Issue:** `zones`, `limits`, `dot`, `doh`, `doq`, `rpz`, `dns64`, `prefetch`, `trust_anchors` validation not called
- **Action:** Add note explaining validation is not automatically invoked
- **Verification:** `rg "fn validate" crates/synvoid-config/src/dns/`

### 4.2 Routing Module Fixes

#### 4.2.1 Replace GitHub URLs with Local Paths
- **File:** `routing_deep_dive.md` or `src/router.rs`
- **Issue:** URLs like `github.com/synvoid/synvoid/blob/main/src/router.rs#L513-L532`
- **Action:** Replace with `src/router.rs:512-532` format
- **Verification:** `rg "github.com" docs/`

#### 4.2.2 Clarify Matching Hierarchy Order
- **File:** `src/router.rs` or routing docs
- **Action:** Note that listener-level default is final fallback only after global matching fails
- **Verification:** `rg "listener.*default|global.*match" src/router.rs`

#### 4.2.3 Document Actual File Structure
- **Issue:** Documents reference `src/routing/` directory which doesn't exist
- **Action:** Explain actual files: `router.rs`, `location_matcher.rs`, `upstream/pool.rs`
- **Verification:** `ls src/router.rs src/location_matcher.rs src/upstream/pool.rs 2>/dev/null || echo "Files at different locations"`

#### 4.2.4 PeakEwma Formula Reference
- **Files:**
  - `src/upstream/pool.rs:513-528` (main formula)
  - `src/upstream/pool.rs:517-521` (cost calculation)
- **Action:** Add second line reference for cost calculation
- **Verification:** `rg "PeakEwma|peak_ewma" src/upstream/`

---

## Wave 5: DNSSEC & DNS Improvements

**Priority: MEDIUM | DNS-specific items**

### 5.1 Fix Anycast Sync Path
- **File:** `src/dns/mesh_sync/` (previously documented as `anycast_sync.rs`)
- **Action:** Update references to `src/dns/mesh_sync/` with `mod.rs`, `dht.rs`, `query.rs`, etc.
- **Verification:** `ls src/dns/mesh_sync/`

### 5.2 Clarify Recursive Resolver Split
- **Files:**
  - `src/dns/recursive.rs` (server wrapper)
  - `src/dns/resolver.rs` (actual resolution using `HickoryResolver`/`HickoryRecursor`)
- **Action:** Document module split clearly
- **Verification:** `rg "HickoryResolver|HickoryRecursor" src/dns/`

### 5.3 Fix TrustAnchorState Sequence
- **File:** `src/dns/dnssec_validation.rs` or related
- **Issue:** Doc shows "Seen → Pending → Valid" but enum is "Missing → Seen → Pending → Valid → Revoked → Removed"
- **Action:** Update documentation to match enum order
- **Verification:** `rg "TrustAnchorState" src/dns/`

### 5.4 Document DNSSEC Signing Validity
- **File:** `src/dns/dnssec_signing.rs:52-54`
- **Action:** Note that RRSIG ±1 day/7 days is hardcoded (non-configurable)
- **Verification:** `rg "RRSIG|validity" src/dns/dnssec_signing.rs`

### 5.5 Monitor TSIG Replay Cache Eviction
- **File:** `src/dns/tsig.rs:46,61-69`
- **Issue:** 10K limit may cause premature eviction under high load
- **Action:** Add monitoring recommendation or increase limit with justification
- **Verification:** `rg "replay.*cache|cache.*evict" src/dns/tsig.rs`

### 5.6 Clarify WireGuard Crate Name
- **Issue:** Document says "boringtun" but crate is `defguard_boringtun`
- **Action:** Update documentation to use `defguard_boringtun`
- **Verification:** `rg "boringtun|defguard" src/tunnel/`

### 5.7 DNS Cookie Validation Toggle
- **File:** `src/dns/cookie.rs:40-42`
- **Issue:** `_enable` parameter is ignored, cookie validation is always enabled
- **Action:** Document this is intentional or file API bug report
- **Verification:** `rg "enable.*cookie|cookie.*enable" src/dns/`

---

## Cross-Cutting Concerns

### Process Lifecycle Documentation

#### Update Overseer Invocation Documentation
- **File:** `architecture/process_lifecycle.md:15`
- **Action:** Note `--master` flag spawns Master, not Overseer directly
- **Verification:** `rg "\-\-master" src/main.rs`

#### Update CLI Flag References
- **File:** `src/main.rs:43`
- **Action:** Add `--worker` flag reference for BaseWorkerProcess
- **Verification:** `rg "\-\-worker" src/main.rs`

#### Add gRPC API Location Note
- **File:** `proto/control.proto`
- **Action:** Note proto file is in `proto/` directory
- **Verification:** `ls proto/control.proto`

#### Clarify Legacy Mode Invocation
- **File:** `architecture/process_lifecycle.md:32`
- **Issue:** Says "cannot be invoked" but code shows it IS reachable via Overseer→Master hierarchy
- **Action:** Clarify invocation path
- **Verification:** `rg "Legacy|legacy" src/overseer/ src/master/`

---

## Verification Commands

```bash
# All profiles should compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Clippy lint
cargo fmt && cargo clippy --lib -- -D warnings

# Test compilation
cargo test --lib --no-run

# Security regression tests
cargo test --test security_regression
```

---

## Deferred Items (Architectural Complexity)

| ID | Issue | Location | Reason |
|----|-------|----------|--------|
| APP-15 | FastCGI Response NOT Truly Streamed | `src/fastcgi/mod.rs:132-164` | Buffers entire stdout; architectural change needed |
| SUP-1 | gRPC Control Plane TLS | `src/supervisor/api.rs:114-129` | Intentional - localhost IPC doesn't need TLS |
| MESH-15 | Quorum Deadlock Risk During Partition | `src/mesh/dht/signed.rs:860-934` | Raft implementation incomplete |

---

## Known Incomplete Items (Not Bugs - Known Limitations)

| Item | Location | Issue |
|------|----------|-------|
| ErasedHttpClient Phase 9 | `src/http/server.rs:3305` | `use_erased_client` hardcoded to `false` |
| HTTP/2 available but not enforced | `src/http_client/mod.rs:893` | `is_http2 = true` hardcoded, uses `http2_only(false)` |
| Minification unused | `src/static_files/mod.rs:134-136` | Params silently ignored |
| Spin instance reuse | `src/spin/runtime.rs:260` | Per-request instantiation overhead |
| GOST DS digest | `src/dns/dnssec_validation.rs:260` | Returns error "not yet supported" |
| DNS Cookie Server not integrated | `src/dns/cookie.rs`, `src/dns/server/mod.rs` | Complete implementation exists but not wired in |

---

## Previously Completed Items (from prior plan)

### Critical Bugs - All Fixed

| ID | Module | Issue | Location | Status |
|----|--------|-------|----------|--------|
| BUG-ROUTER-1 | Routing | Hardcoded port 80 instead of configured port | `src/router.rs:1318` | ✅ FIXED |
| BUG-PLUGIN-1 | Plugin/WASM | DHT prefix examples wrong (security risk) | `architecture/plugin_deep_dive.md:87-88` | ✅ FIXED |
| BUG-PL-1 | Process Lifecycle | Missing `--master` CLI flag | `src/main.rs` | ✅ ALREADY FIXED |
| BUG-L1 | Layer 3.5 | `verify_hybrid()` fail-safe | `src/mesh/ml_dsa.rs:217` | ✅ ALREADY FIXED |
| BUG-L3 | Layer 3.5 | ML-KEM key exchange proof-of-possession | `src/mesh/ml_kem_key_exchange.rs:204-265` | ✅ FIXED |

---

*Plan consolidated 2026-05-26 from individual review plans*
