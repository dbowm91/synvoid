# Routing Architecture Review Plan

## Summary

Cross-referenced `architecture/routing_deep_dive.md` against `src/router.rs` (1423 lines) and `src/upstream/pool.rs` (1540 lines). The document is largely accurate but has some line number references that need correction and minor gaps.

---

## Discrepancies and Issues Found

### 1. parse_quictunnel_url Line Range Incorrect

**Document claims:** `src/router.rs#L513-L532` for `parse_quictunnel_url()`  
**Actual location:** `src/router.rs:513-532` (function starts at line 513, ends at line 532)

The link format uses `#L513-L532` but GitHub renders this as lines 513 to 532. The actual function spans lines 513-532, so the range is technically correct, but the notation style is inconsistent with other references in the codebase (which use single line numbers like `:513`).

**Recommendation:** Use `#L513` or clarify if the range is intentional (start to end inclusive).

---

### 2. BUG-ROUTER-1 Reference Misleading

**Document references:** "Hardcoded port 80 (BUG-ROUTER-1 was fixed at `src/router.rs:1318`)"  
**Actual state:** Line 1318 contains `if !config_arc.site.listen.is_empty()` - not the bug fix. The default `server_port: 80` is at `src/router.rs:1420` in the `Default` impl.

The bug fix for hardcoded port 80 was in a different location. The current `Router::new()` at line 105+ uses `main_config.server.port` correctly. The `server_port: 80` at line 1420 is only for the `Default` impl, which is appropriate for fallback construction.

**Recommendation:** Remove or update the BUG-ROUTER-1 reference since the document's line number doesn't match where the bug manifestation was discussed.

---

### 3. Load Balancing Algorithm Line Reference Missing

**Document claims:** PeakEwma formula is at `src/upstream/pool.rs:48-57`  
**Actual location:** The `LoadBalanceAlgorithm` enum is at `src/upstream/pool.rs:48-57`, but the actual PeakEwma calculation is at `src/upstream/pool.rs:513-528`.

The enum definition (lines 48-57) defines the algorithm variant, but the cost calculation `(conn + 1.0) * (latency + 1.0)` is at lines 520-521.

**Recommendation:** Update reference to `src/upstream/pool.rs:513-528` for the full algorithm implementation.

---

### 4. Document Lacks Coverage of Connection Pool Lifecycle

The "Connection Lifecycle" section (lines 76-82) only provides a high-level overview but does not reference actual implementation details.

The actual lifecycle involves:
- `UpstreamPool::acquire()` - requests connection from pool
- `increment_connections()` / `decrement_connections()` - connection counting
- `BackendProtocol` handling (HTTP/1.1 keep-alive, H2 multiplexing)
- Connection timeout and idle timeout management

**Recommendation:** Add reference to `src/upstream/pool.rs:545-580` for `select_next_backend()` and connection management.

---

### 5. Health Monitoring Implementation Not Documented

The document mentions "Passive Health Checks" and "Active Health Checks" but does not reference the actual implementation:

- Passive checks: `src/upstream/health.rs` (lines 1-200+)
- Active checks: `HealthChecker` trait and implementations
- Failure thresholds: configured via `HealthCheckConfig`

**Recommendation:** Add a subsection or note pointing to `src/upstream/health.rs` for health monitoring implementation.

---

### 6. BackendType Enum Verification - CORRECT

**Document claims:** 11 BackendType variants  
**Actual code:** `src/router.rs:66-78` has exactly:
```rust
pub enum BackendType {
    Upstream,       // 1
    FastCgi,        // 2
    Php,            // 3
    Cgi,            // 4
    AxumDynamic,    // 5
    AppServer,      // 6
    Static,         // 7
    QuicTunnel,     // 8
    Serverless,     // 9
    Mesh,           // 10
    Spin,           // 11
}
```
**Status:** ✅ CORRECT

---

### 7. PeakEwma Formula - CORRECT

**Document claims:** `(conn + 1) * (latency + 1)` at `src/upstream/pool.rs:48-57`  
**Actual code:** `src/upstream/pool.rs:520-521`:
```rust
let cost = (conn + 1.0) * (latency + 1.0);
```
**Status:** ✅ CORRECT (line reference needs updating)

---

## Minor Suggestions for Improvement

### A. Add "Lease" Clarification
The architecture document correctly does NOT mention "lease" - this concept doesn't exist in the codebase. This is good.

### B. Radix Tree Implementation Note
The document describes the reverse-domain Radix tree approach. The actual implementation uses `matchit::Router` (line 35 in router.rs), not a custom Radix tree. The `MatchRouter` provides O(k) lookup where k is the number of path segments.

**Recommendation:** Clarify that the wildcard matching uses `matchit` crate's `Router` type, not a custom Radix implementation.

### C. QuicTunnel URL Parsing Coverage
The document mentions `parse_quictunnel_url()` at both location and site levels. Verified at:
- `src/router.rs:558` - location-level parsing
- `src/router.rs:860` - site-level parsing

**Status:** ✅ CORRECT

---

## Security Considerations

No security issues found in routing logic. The code properly handles:
- URL validation in `validate_upstream_url()` (`src/upstream/pool.rs:14-46`)
- Scheme restrictions (only http, https, ws, wss, grpc, grpcs allowed)
- Unsafe schemes (file://, ftp://, gopher://) are blocked

---

## Documentation Quality Rating

| Aspect | Rating | Notes |
|--------|--------|-------|
| BackendType enum | ✅ Accurate | 11 variants correctly listed |
| Load balancing algorithms | ✅ Mostly accurate | PeakEwma formula correct, line ref needs update |
| Matching hierarchy | ✅ Accurate | Uses matchit Router correctly described |
| QuicTunnel URL parsing | ✅ Accurate | Both location and site level parsing verified |
| Connection lifecycle | ⚠️ Incomplete | High-level only, no implementation references |
| Health monitoring | ⚠️ Missing | Mentioned but not linked to implementation |
| Line number references | ⚠️ Some outdated | BUG-ROUTER-1 reference misleading |

---

## Recommended Actions

1. **Update line references** in routing_deep_dive.md:
   - Change `src/upstream/pool.rs:48-57` → `src/upstream/pool.rs:513-528` for PeakEwma
   - Clarify BUG-ROUTER-1 reference or remove it
   - Use consistent line reference format (single line or range)

2. **Add implementation references**:
   - Connection lifecycle: `src/upstream/pool.rs:545-580`
   - Health monitoring: `src/upstream/health.rs`
   - Radix tree implementation: `matchit` crate usage at `src/router.rs:34-35`

3. **Clarify architectural vs implementation**:
   - The document correctly presents high-level architecture
   - Consider adding an "Implementation Details" section for developers

---

*Review completed: 2026-05-26*
*Cross-referenced: src/router.rs (1423 lines), src/upstream/pool.rs (1540 lines), src/upstream/health.rs*