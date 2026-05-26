# Routing Architecture Review Plan

Based on review of `architecture/routing_deep_dive.md` against `src/router.rs` and related routing code.

---

## Stale Items Identified

### 1. "AppServer (Granian)" branding is outdated
- **Document says:** `AppServer (Granian): Built-in support for Python ASGI/WSGI applications.`
- **Actual code:** `src/router.rs:71` - `AppServer` is a generic enum variant with no "Granian" branding
- **Impact:** Low - branding may have been removed but functionality remains

### 2. Backend Types list is incomplete
- **Document lists (lines 38-46):** Upstream, FastCGI/PHP, Static, AppServer, Serverless (WASM), Mesh, QuicTunnel
- **Actual code has additional types in `src/router.rs:65-77`:**
  - `AxumDynamic` - NOT documented
  - `Spin` - NOT documented (mentioned in skills/spin_wasm.md but not main routing doc)
  - `Cgi` - NOT documented
  - `Php` - documented as FastCGI variant but is separate enum variant

### 3. Connection Lifecycle "Lease" concept missing
- **Document says (line 74):** "Lease: A connection is requested from the pool (enforcing limits)"
- **Actual code:** `src/upstream/pool.rs` uses `increment_connections()` / `decrement_connections()` - no "lease" terminology or implementation exists
- **Impact:** Documentation implies a more sophisticated feature than what exists

### 4. LocationMatcher comment references non-existent code
- **Document references (implied):** trie-based `find_best_match` in location matching
- **Actual code:** `src/location_matcher.rs:114` says "A previous trie-based implementation (find_best_match) was removed as dead code" but no such method exists in codebase
- **Impact:** Documentation is stale but harmless - the removal happened and current implementation is correct

---

## Claims Verified / Issues Found

### VERIFIED: Matching Hierarchy (lines 9-15)
**Status:** ✅ CORRECT

Code at `src/router.rs:1137-1187` confirms the order:
1. IP-based exact domain match (line 1139)
2. IP-based wildcard match (lines 1144-1149)
3. Global exact domain_map (line 1164)
4. Global wildcard_domain_router using reversed-domain Radix tree (lines 1169-1172)
5. Default server fallback (lines 1174-1186)
6. Path-based matching via LocationMatcher

### VERIFIED: Reverse-Domain Radix Tree (lines 17-34)
**Status:** ✅ CORRECT

- `src/router.rs:1375-1379` - `reverse_domain_for_router()` correctly reverses domains
- Uses `matchit::Router` for O(k) wildcard lookups
- Implementation matches document exactly

### VERIFIED: Load Balancing Algorithms (lines 53-60)
**Status:** ✅ CORRECT

`src/upstream/pool.rs:48-57` declares:
- RoundRobin (default)
- Random
- LeastConnections
- PeakEwma (NOT mentioned in doc - missing)
- WeightedRoundRobin
- IpHash

**Missing from doc:** PeakEwma algorithm

### VERIFIED: Health Monitoring (lines 62-67)
**Status:** ✅ CORRECT

- Passive checks: `src/upstream/pool.rs:324-343` - consecutive failures/successes tracking
- Active checks: `src/upstream/health.rs` - periodic HTTP GET/HEAD/TCP connect checks
- Connection limits: `src/upstream/pool.rs:281-284` - max_connections enforcement
- Backup servers: `src/upstream/pool.rs:409-427` - `new_with_backup()` method

### ISSUE: Backend Resolution inconsistencies
**Status:** ⚠️ INCONSISTENT

`src/router.rs:833-1122` - `route_to_target()` function:
- Site-level backend QuicTunnel parsing (line 858) but location-level doesn't parse QuicTunnel URLs
- Location-level has more backend types (AxumDynamic, Spin) than site-level
- The logic is duplicated but not identical between the two paths

### ISSUE: `update_sites` hardcodes port 80
**Status:** 🐛 BUG

`src/router.rs:1318`:
```rust
if let Some(addr) = listen_config.to_socket_addr(80) {
```
Should use `main_config.server.port` instead of hardcoded `80`. This is a regression from the original `build_all_maps` which correctly uses the configured port.

---

## Improvement Plan

### High Priority

1. **Fix hardcoded port in `update_sites`** (`src/router.rs:1318`)
   - Change `listen_config.to_socket_addr(80)` to use the configured port
   - This causes incorrect IP-to-site bindings when server port != 80

2. **Add PeakEwma to documented load balancing algorithms**
   - Document at `architecture/routing_deep_dive.md` line 55 is missing PeakEwma

3. **Document AxumDynamic backend type**
   - Add to backend types list (lines 38-46)
   - AxumDynamic is a significant feature for plugin-based dynamic handling

### Medium Priority

4. **Unify QuicTunnel URL parsing between location and site levels**
   - `src/router.rs:556-570` (location) vs `src/router.rs:858-872` (site)
   - Location-level doesn't parse quictunnel:// URLs

5. **Update "AppServer (Granian)" branding**
   - Either document Granian specifically or remove "(Granian)" from doc

6. **Document Spin backend type**
   - Spin is a valid backend type per `src/router.rs:76`

### Low Priority

7. **Update Connection Lifecycle description**
   - Remove "Lease" terminology if no lease mechanism exists
   - Or implement proper lease tracking if needed

8. **Fix LocationMatcher documentation**
   - Comment at `src/location_matcher.rs:114` references removed `find_best_match`
   - Consider removing or updating this comment

---

## Bug Report

### Critical

None identified.

### Minor

| Bug ID | Location | Description |
|--------|----------|-------------|
| BUG-ROUTER-1 | `src/router.rs:1318` | `update_sites` uses hardcoded port 80 instead of `main_config.server.port` |
| BUG-ROUTER-2 | `src/router.rs:556-570` vs `858-872` | QuicTunnel URL parsing not applied at location level |

---

## Summary

The routing architecture document is **largely accurate** but has several stale items:

- **Stale content:** Missing backend types (AxumDynamic, Spin, Cgi), missing algorithm (PeakEwma), outdated branding (Granian)
- **Actual bugs:** Hardcoded port 80 in `update_sites` is a regression
- **Documentation gaps:** Connection lifecycle "lease" concept doesn't match implementation

The core routing logic (matching hierarchy, Radix tree, location matching) is correctly documented and verified against the code.
