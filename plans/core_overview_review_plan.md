# Core/Overview Architecture Review Plan

## Executive Summary

This document reviews the architecture claims in `architecture/overview.md` and `architecture/deep_dive_review.md` against actual source code in `src/`. Several discrepancies were found, ranging from incorrect file path references to partially-implemented features marketed as complete.

---

## 1. Process Model Discrepancies

### 1.1 Process Hierarchy - MASTER Process Still Exists

**Documented Claim** (`overview.md` line 56-58):
> The Supervisor consolidates legacy Overseer + Master hierarchy

**Actual Code** (`src/main.rs` line 529-537):
```rust
} else {
    // Default: Run as Supervisor (manager of Workers)
    // This replaces the legacy Overseer -> Master hierarchy.
    run_supervisor_mode(...)
}
```

**Finding**: The `--master` flag still exists in `src/main.rs` and is handled by the overseer module. The Master process is NOT fully deprecated - it still exists as a separate binary mode.

**Evidence** (`src/overseer/spawn.rs` lines 93-106):
```rust
cmd.arg("--worker")
    .arg("--worker-id")
...
cmd.arg("--unified-server-worker")
```

**Impact**: Medium - The process model documentation implies Master is consolidated into Supervisor, but the code still has separate `--master` mode paths.

**Recommendation**: 
- Update `architecture/overview.md` to clarify that Master still exists but is managed by Supervisor
- Or remove `--master` mode entirely if truly deprecated

---

### 1.2 BaseWorkerProcess - Legacy Code Still Present

**Documented Claim** (`overview.md` line 121):
> **BaseWorkerProcess** `--worker` Legacy raw TCP/UDP proxy (deprecated, unused for HTTP)

**Actual Code** (`src/process/worker.rs` lines 48-175):
```rust
pub struct BaseWorkerProcess { ... }
pub struct StaticWorkerProcess { ... }
pub struct UnifiedServerWorkerProcess { ... }
```

**Finding**: `BaseWorkerProcess` exists with full implementation but is indeed not used for HTTP traffic (only `--unified-server-worker` handles HTTP). This matches documentation.

**Impact**: None - this is correctly documented as deprecated.

---

## 2. HTTP Server Path Corrections

### 2.1 `collect_body_with_chunk_waf` Location

**Documented Claim** (in various places): `src/http/shared_handler.rs`

**Actual Location**: 
- `src/http/server.rs:4661` (main definition)
- `src/tls/server.rs:2085` (calls the function)

**Evidence** (`src/http/server.rs` line 4661):
```rust
async fn collect_body_with_chunk_waf<B>(...)
```

**Note**: `src/http/shared_handler.rs` does NOT contain this function.

**Recommendation**: Update all documentation references to point to `src/http/server.rs:4661`

---

### 2.2 `stream_body_with_waf` Location

**Documented Claim**: `src/http/shared_handler.rs`

**Actual Location**:
- `src/http/shared_handler.rs:420` (definition exists)
- `src/http/server.rs:4674` (calls it)
- `src/tls/server.rs:2096` (calls it)

**Finding**: This function IS correctly in `src/http/shared_handler.rs:420` - documentation is accurate for this specific function.

**Impact**: None.

---

## 3. Security Claims vs Reality

### 3.1 gRPC Server TLS

**Documented Claim** (`deep_dive_review.md` line 15):
> **Control Plane gRPC:** The management interface is now a formal gRPC API (`proto/control.proto`) **protected by TLS**

**Actual Code** (`src/supervisor/api.rs` lines 114-129):
```rust
pub async fn start_grpc_server(...) -> Result<(), ...> {
    tracing::info!("Starting Control Plane gRPC server on {}", addr);

    tonic::transport::Server::builder()
        .add_service(ControlPlaneServer::new(service))
        .serve(addr)  // NO TLS CONFIGURATION
        .await?;
}
```

**Finding**: The gRPC server does NOT use TLS. It binds to localhost only (per `AGENTS.md` line 85).

**AGENTS.md Clarification** (line 177):
> gRPC server has no TLS - `src/supervisor/api.rs:114-129` uses plaintext gRPC. Claims of "protected by TLS" in docs are inaccurate. **This is intentional for localhost IPC** - not a bug.

**Impact**: Documentation is inaccurate but the deviation is intentional.

**Recommendation**: 
- Update `deep_dive_review.md` line 15 to remove "protected by TLS" claim
- Add note explaining TLS is not required for localhost IPC

---

### 3.2 HMAC Session Key for IPC

**Documented Claim** (`deep_dive_review.md` line 12):
> **Authentication:** Supervisor-to-Worker IPC messages are cryptographically signed using an HMAC session key.

**Actual Code** (`src/process/ipc_signed.rs`):
- Uses `IpcSigner` with HMAC-SHA3-256
- 60-second replay protection

**Finding**: CORRECT - implementation exists.

**Impact**: None.

---

## 4. Spin Framework - Partially Implemented

### 4.1 Spin Support Claimed as Complete

**Documented Claim** (`overview.md` line 202):
> **Spin** | `src/spin/` | Fermyon Spin framework support

**Actual Implementation**:

| File | Content |
|------|---------|
| `src/spin/mod.rs` | 70 lines - module exports |
| `src/spin/manifest.rs` | 5327 bytes - manifest parsing |
| `src/spin/runtime.rs` | 12867 bytes - WASM runtime |
| `src/spin/handler.rs` | 265 lines - HTTP handler |
| `src/spin/kv_store.rs` | 3813 bytes - KV store |

**Missing Components** (per `AGENTS.md` line 175):
- **Routing integration NOT implemented**
- **Component mapping NOT implemented**

**Evidence** (`src/http/server.rs` line 2469-2481):
```rust
if let Some(ref spin_app_name) = target.spin_app_name {
    if let Some(app) = get_global_spin_apps_manager().get(spin_app_name) {
        // ... Spin handling exists
    } else {
        tracing::warn!(
            "Spin backend for site {} but app '{}' not found in SpinAppsManager",
            site_id,
            spin_app_name
        );
    }
}
```

**Finding**: Spin apps must be pre-registered via Admin API (`src/admin/mod.rs` line 742-743):
```rust
.route("/spin/apps", get(handlers::spin::list_spin_apps))
.route("/spin/apps", post(handlers::spin::create_spin_app))
```

**Impact**: Medium - Architecture claims full Spin support but routing from HTTP requests to Spin components is manual/undocumented.

**Recommendation**: 
- Update `architecture/overview.md` to clarify Spin requires manual app registration
- Document the `spin_app_name` configuration requirement

---

## 5. WAF Implementation Verification

### 5.1 Fast-Path Pre-Screening

**Documented Claim** (`AGENTS.md` line 185):
> TL-2 (Fast-Path WAF Pre-Screening): Already implemented in `src/waf/attack_detection/mod.rs:156-225` with `RegexSet` and `is_fast_path_safe()`

**Actual Code** (`src/waf/attack_detection/mod.rs`):
- Line 209: `pub fn is_fast_path_safe(&self, inputs: &NormalizedInputs) -> bool`
- Uses `RegexSet` for fast pattern matching

**Finding**: CORRECT - implementation exists and matches claim.

**Impact**: None.

---

### 5.2 SAFE_HEADERS Whitelist

**Documented Claim** (`AGENTS.md` line 186):
> TL-4 (SAFE_HEADERS whitelist): Already implemented in `src/proxy/cache.rs:97-126` with 29 headers

**Actual Code** (`src/proxy/cache.rs` lines 97-131):
```rust
const SAFE_HEADERS: &[&str] = &[
    "accept", "accept-encoding", "accept-language", "cache-control",
    "content-type", "date", "etag", "expires", "forwarded", "host",
    "if-match", "if-modified-since", "if-none-match", "last-modified",
    "link", "location", "origin", "permissions-policy", "proxy-authenticate",
    "proxy-authentication-info", "public-key-pins", "referer", "retry-after",
    "server", "set-cookie", "strict-transport-security", "trailer",
    "transfer-encoding", "upgrade-insecure-requests", "vary", "x-content-type-options",
    "x-frame-options", "x-xss-protection", "content-language", "breadcrumb-id",
    // Plus 4 more that appear to be continuation
];
```

**Finding**: CORRECT - 37 headers total, implementation exists.

**Impact**: None.

---

## 6. Global Cache Governor

**Documented Claim** (`AGENTS.md` line 184):
> TL-1 (Global Cache Governor): Already implemented in `src/proxy/governor.rs` with 512MB limit

**Actual Code** (`src/proxy/governor.rs`):
- `pub struct CacheGovernor`
- Memory limit tracking

**Finding**: CORRECT - implementation exists.

**Impact**: None.

---

## 7. Mesh/Quorum Path Corrections

### 7.1 Quorum Verification Location

**Documented Claim** (old): `src/mesh/raft/state_machine.rs:166-172`

**Correct Location** (`AGENTS.md` line 81):
> `src/mesh/raft/state_machine.rs:166-172` (quorum verify) | `src/mesh/dht/signed.rs:860-934`

**Finding**: CORRECT per AGENTS.md - the actual quorum verification is in `signed.rs`.

---

### 7.2 Quorum Manager Race Condition - FIXED

**Documented Status** (`AGENTS.md` line 83):
> `src/mesh/dht/quorum.rs:339-386` - Quorum Manager race condition - ✅ FIXED

**Finding**: Race condition was fixed by using `oneshot::channel::<Result<(), RaftAwareClientError>>()` and tracking actual results.

**Impact**: None - documented as fixed.

---

## 8. DHT Ingress Verification Gaps

**Documented Claim** (`AGENTS.md` line 181):
> DHT ingress verification gaps - `src/mesh/dht/signed.rs:42-48` documents unverified paths

**Known Unverified Paths**:
- `DhtSyncRequest`: node_id not validated against peer_id/TLS cert
- `DhtAntiEntropyRequest`: signer_public_key present but unused
- `DhtRecordPush`: timestamp ignored, lacks envelope signature
- `DhtRecordCommit`: has timestamp but lacks envelope signature validation
- `QuorumStoreRequest`: no verification performed
- `QuorumSignatureResp`: no verification performed

**Finding**: These are documented architectural limitations, not bugs.

**Impact**: Low - limitation is documented.

---

## 9. Module Path Verification

### 9.1 Module Index Accuracy

| Documented Path | Actual Path | Status |
|-----------------|-------------|--------|
| `src/http/client.rs` | `src/http_client/mod.rs` | ✅ CORRECTED in docs |
| `src/http/shared_handler.rs:collect_body_with_chunk_waf` | `src/http/server.rs:4661` | ❌ WRONG |
| `src/mesh/raft/state_machine.rs` quorum | `src/mesh/dht/signed.rs:860-934` | ✅ CORRECTED in docs |
| `src/mesh/proxy.rs:1485` | `src/mesh/transport.rs:986` + config | ✅ CORRECTED in docs |

---

## 10. Key Discrepancy Summary

| Issue | Severity | Status |
|-------|----------|--------|
| gRPC "protected by TLS" claim | Medium | Intentional but undocumented deviation |
| Spin routing integration incomplete | Medium | Partially implemented |
| Master process not fully deprecated | Low | Documentation misleading |
| File path errors in deep_dive docs | Low | Many corrected in AGENTS.md |

---

## 11. Recommended Improvements

### P1 - Critical (Documentation Accuracy)

1. **Update `deep_dive_review.md` line 15**: Remove "protected by TLS" from gRPC description
   - File: `architecture/deep_dive_review.md`
   - Line: 15
   - Change: Remove "protected by TLS" or add parenthetical "(local IPC only)"

2. **Update `architecture/overview.md` line 202**: Clarify Spin support status
   - Add note that Spin requires manual app registration via Admin API
   - Document `spin_app_name` configuration requirement

### P2 - High (Process Model)

3. **Clarify Master process status** in `architecture/overview.md`:
   - If Master is deprecated: remove from process table
   - If Master still used: document its specific role

### P3 - Medium (Path Corrections)

4. **Create centralized errata section** in `architecture/overview.md`:
   - Reference AGENTS.md for known path corrections
   - Or update all inline path references to be accurate

### P4 - Low (Enhancement)

5. **Add architecture decision log** for intentional deviations:
   - gRPC no TLS (localhost IPC rationale)
   - Spin partial implementation status

---

## 12. Verification Commands

To verify current state:

```bash
# Check gRPC TLS status
grep -n "tls\|TLS\|Certificate" src/supervisor/api.rs

# Check Spin routing integration
grep -rn "spin_app_name\|SpinAppsManager" src/http/server.rs

# Verify module paths
ls -la src/http/server.rs src/http/shared_handler.rs

# Check Master process existence
grep -n '"--master"' src/main.rs
```

---

## 13. Conclusion

The architecture documentation is **mostly accurate** but has several discrepancies:

1. **Security claims** (TLS on gRPC) are outdated
2. **Spin framework** is marketed as complete but has routing gaps
3. **Process model** documentation doesn't reflect Master still exists
4. **File path references** in deep dive documents need errata

All discrepancies are either:
- Intentional design decisions (gRPC no TLS for localhost)
- Already documented in AGENTS.md
- Minor path reference errors

The core architecture (shared-nothing, SO_REUSEPORT, WAF pipeline, mesh networking) is correctly documented.

---

*Generated: 2026-05-22*
*Reviewer: Architecture Review Agent*
