# Worker Architecture Review - 2026-05-27

## Verified Correct Items

### File Paths and Line Numbers
- **`BufferPool`** at `crates/synvoid-utils/src/buffer/pool.rs:211` - Struct definition confirmed
- **`BufferPoolConfig`** at line 242 - Config struct confirmed
- **`/health`** endpoint at `src/admin/mod.rs:180` - Confirmed via `route("/health", get(health_check))`
- **`/serverless/health`** endpoint at `src/admin/handlers/serverless.rs:122` - OpenAPI path annotation confirmed
- **`/__internal__/health`** at `src/http/server.rs:286` - Constant confirmed
- **HTTP/2 ALPN negotiation** at `src/tls/server.rs:411-487` - Code confirms ALPN-based protocol negotiation
- **`WafCore::check_request_full`** pipeline order matches documentation:
  1. Block Store Check (line 456)
  2. Rate Limits (line 460)
  3. Endpoint Block (line 464)
  4. Honeypot Detection (line 468)
  5. Bot Protection (line 472)
  6. Flood Protection (line 476)
  7. Attack Detection (line 487)

### Buffer Pool Architecture
- Sharded mutex design confirmed (line 212: `shards: Vec<Shard>`)
- Three-tier structure: small (4KB), medium (32KB), large (128KB), jumbo (256KB)
- Global and thread-local acquisition variants confirmed (lines 287-293)
- Configurable via `BufferPoolConfig` (lines 241-263)

### Worker Startup Sequence
- Sequence in documentation matches `run_unified_server_worker` implementation:
  - Initialize ConfigManager (line 121)
  - Load site configurations (line 129)
  - Start TcpListenerPool (via UnifiedServer)
  - Initialize WAF pipeline (line 501)
  - Start upstream connection pools (via UnifiedServer)
  - Begin accepting connections (line 1781)

### Process Hierarchy
- Default entry point correctly shows `run_supervisor_mode()` at `src/main.rs:541-546`
- `--unified-server-worker` flag handled at lines 499-524
- Supervisor replaces legacy Overseer hierarchy (line 540 comment confirms this)

---

## Discrepancies Found

### 1. HTTP/2 Client-Side Documentation Inaccuracy
**Document says:** "Client-side has hardcoded `is_http2 = true` in `src/http_client/mod.rs:893`"

**Actual code at line 893:**
```rust
match tokio::time::timeout(t, client.send_request(req, authority, is_http2, Some(t))).await
```
The `is_http2` parameter is **not hardcoded** - it comes from the function parameter at line 878:
```rust
is_http2: bool,
```

**Fix:** Documentation should state that HTTP/2 is configurable via `ProxyServer::with_http2()` method (as noted in AGENTS.md WRK-BUG-1).

### 2. Health Endpoint Routing Discrepancy
**Document says:** `src/admin/handlers/serverless.rs:122` is a health endpoint

**Actual location:**
- Handler defined at `src/admin/handlers/serverless.rs:122` ✓
- BUT it's registered in the **Admin API** router (`src/admin/mod.rs:736`), not the UnifiedServer
- The document lists this under "Worker Startup Sequence" suggesting it's worker-specific, but it's actually an admin endpoint

**Impact:** Low - endpoint works correctly, just documented in wrong context.

### 3. Mesh Control Plane Documentation Incorrect
**Document says:** "Mesh and Threat Intelligence Initialization" in unified server worker

**Actual behavior at lines 620-655:**
```rust
if true {  // Always true - mesh control plane is disabled
    tracing::info!("Mesh control plane is disabled in worker process");
    // Creates dummy ThreatIntelligenceManager
}
```

The code explicitly disables mesh control plane in workers with `if true { ... }` block (line 622), creating a dummy threat intel instead of real mesh integration.

**Impact:** Documentation misleading - actual implementation relegates mesh to Supervisor process, not worker.

### 4. BufferPool Tier Count Mismatch
**Document says:** "Three tiers: small (4KB), medium (32KB), large (128KB)"

**Actual implementation at `pool.rs:201-207`:**
```rust
small: TierArena::new(SMALL_BUF_SIZE, SMALL_POOL_CAP / NUM_SHARDS),   // 4KB
medium: TierArena::new(MEDIUM_BUF_SIZE, MEDIUM_POOL_CAP / NUM_SHARDS), // 32KB
large: TierArena::new(LARGE_BUF_SIZE, LARGE_POOL_CAP / NUM_SHARDS),   // 128KB
jumbo: TierArena::new(256 * 1024, JUMBO_POOL_CAP / NUM_SHARDS),        // 256KB
```

**There are FOUR tiers, not three.**

---

## Bugs Identified

### BUG-WORKER-1: Documentation States "Hardcoded" HTTP/2 When It's Configurable
**Severity:** Low (Documentation only)
**Location:** `architecture/worker_architecture.md:36`
**Issue:** States client-side HTTP/2 is hardcoded when it's actually configurable via `ProxyServer::with_http2()`
**Status:** Code is correct, documentation is outdated
**Fix:** Update doc to remove "hardcoded" claim

### BUG-WORKER-2: `upgrade_mode` Hardcoded to `false` in CLI Builder
**Severity:** Low (Missing CLI functionality)
**Location:** `src/startup/worker.rs:41`
**Issue:** The `upgrade_mode` field in `UnifiedServerWorkerArgs` exists and is properly defined in the struct, but in `build_unified_server_worker_args()` it's hardcoded to `false`:
```rust
UnifiedServerWorkerArgs {
    ...
    upgrade_mode: false,  // Always false, not configurable via CLI
    reuse_port: false,
    ...
}
```
The CLI `--unified-server-worker` flag doesn't provide options to set `upgrade_mode` or `reuse_port`. If these are intentional defaults, fine - but if `upgrade_mode` should be configurable, the CLI is missing that option.
**Status:** Field exists and compiles, but CLI doesn't expose it

### BUG-WORKER-3: Port Honeypot Documentation Location Wrong
**Severity:** Low (Documentation organization)
**Location:** `architecture/worker_architecture.md` - listed under "Worker Startup Sequence"
**Issue:** Port honeypot is initialized in worker but documented as if it's part of startup sequence. The actual initialization happens at lines 546-594 in `unified_server.rs`, not as a startup step.

---

## Suggested Improvements

### 1. Clarify HTTP/2 Configuration Status
**Current:** "Client-side has hardcoded `is_http2 = true`"
**Proposed:** "Client-side HTTP/2 is configurable via `ProxyServer::with_http2()` (defaults to HTTP/1.1 for broader compatibility)"

### 2. Fix Buffer Pool Tier Count
**Current:** "Three tiers: small (4KB), medium (32KB), large (128KB)"
**Proposed:** "Four tiers: small (4KB), medium (32KB), large (128KB), jumbo (256KB)"

### 3. Reorganize Health Endpoint Documentation
Move `/serverless/health` from "Worker Startup Sequence" section to "Admin API" or create separate "Health Check Endpoints" section noting:
- `/health` - Basic status (admin API)
- `/serverless/health` - Serverless runtime status (admin API)
- `/__internal__/health` - Detailed worker status (internal)

### 4. Document Mesh Control Plane Decision
The documentation claims mesh runs in workers, but code shows it's disabled. Either:
- Update docs to reflect "Mesh control plane runs in Supervisor process, workers receive intelligence via IPC"
- Or update code to actually enable mesh in workers if that's the intent

### 5. Add Cross-Reference to AGENTS.md
Add note that HTTP/2 upstream configuration is documented as fixed in AGENTS.md (WRK-BUG-1) and should not be considered a bug.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 9 |
| Discrepancies | 4 |
| Bugs (Documentation) | 3 |
| Suggested Improvements | 5 |

**Overall Assessment:** The architecture document is largely accurate. Most issues are documentation-only (outdated claims about HTTP/2 being "hardcoded", wrong tier count). The code implementation is solid and follows the documented architecture reasonably well. The most significant issue is the mesh control plane claim which doesn't match the actual `if true { ... }` disable block in the code.