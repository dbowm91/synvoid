# Routing Module Review Plan

## Document Analyzed
`architecture/routing_deep_dive.md` - Request Routing & Upstream Management

---

## 1. Claims Verified/Not Verified with Code Locations

### 1.1 Routing Engine - Matching Hierarchy

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Listener-Level Default fallback | **VERIFIED** | `src/router.rs:1174-1187`, `src/router.rs:420-431` | Default servers configured via `default_servers` HashMap, fallback on `*` or empty host |
| Exact Domain Matching | **VERIFIED** | `src/router.rs:1164-1166` | `domain_map.get(clean_host_arc.as_ref())` |
| Wildcard/Suffix Matching | **VERIFIED** | `src/router.rs:1169-1172`, `src/router.rs:271-275` | Uses `reverse_domain_for_router()` with MatchRouter radix tree |
| Path-Based Matching (Locations) | **VERIFIED** | `src/router.rs:543-545`, `src/location_matcher.rs:236-264` | `LocationMatcher.match_uri()` with exact, prefix, regex support |

### 1.2 Backend Types

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Upstream | **VERIFIED** | `src/router.rs:65-77` | `BackendType::Upstream` exists |
| FastCGI / PHP | **VERIFIED** | `src/router.rs:67-68` | `BackendType::FastCgi` and `BackendType::Php` both exist |
| Static | **VERIFIED** | `src/router.rs:72` | `BackendType::Static` exists |
| AppServer (Granian) | **VERIFIED** | `src/router.rs:71` | `BackendType::AppServer` exists |
| Serverless (WASM) | **VERIFIED** | `src/router.rs:74` | `BackendType::Serverless` exists |
| Mesh | **VERIFIED** | `src/router.rs:75` | `BackendType::Mesh` exists (feature-gated) |
| QuicTunnel | **VERIFIED** | `src/router.rs:73` | `BackendType::QuicTunnel` exists |
| **Spin** (not in doc) | **VERIFIED** | `src/router.rs:76` | `BackendType::Spin` exists but not documented |
| **AxumDynamic** (not in doc) | **VERIFIED** | `src/router.rs:70` | `BackendType::AxumDynamic` exists but not documented |
| **CGI** (not in doc) | **VERIFIED** | `src/router.rs:69` | `BackendType::Cgi` exists but not documented |

### 1.3 Load Balancing Algorithms

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Round Robin (Default) | **VERIFIED** | `src/upstream/pool.rs:48-56`, `src/upstream/pool.rs:431-438` | Default algorithm, `apply_round_robin()` |
| Weighted Round Robin | **VERIFIED** | `src/upstream/pool.rs:54`, `src/upstream/pool.rs:566-583` | `weighted_round_robin()` implemented |
| Least Connections | **VERIFIED** | `src/upstream/pool.rs:52`, `src/upstream/pool.rs:451-457` | `apply_least_connections()` using `composite_load()` |
| Random | **VERIFIED** | `src/upstream/pool.rs:51`, `src/upstream/pool.rs:440-449` | `apply_random()` using `rand::Rng` |
| IP Hash | **VERIFIED** | `src/upstream/pool.rs:55`, `src/upstream/pool.rs:459-477` | `apply_ip_hash()` implemented |
| **PeakEwma** (not in doc) | **VERIFIED** | `src/upstream/pool.rs:53`, `src/upstream/pool.rs:495-510` | `PeakEwma` algorithm exists but not documented |
| **Weighted Round Robin** mentioned in doc but not explained | **VERIFIED** | Same as above | Algorithm exists |

### 1.4 Health Monitoring & Resilience

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Passive Health Checks | **VERIFIED** | `src/upstream/pool.rs:323-342` | `record_success()` and `record_failure()` with 3-consecutive threshold |
| Active Health Checks | **PARTIAL** | `src/fastcgi/pool.rs:148-157` | Only `FastCgiPool` has active health check thread; **UpstreamPool does NOT** |
| Connection Limits | **VERIFIED** | `src/upstream/pool.rs:274-283` | `max_connections` on Backend |
| Backup Servers | **VERIFIED** | `src/upstream/pool.rs:393-409`, `src/upstream/pool.rs:517-525` | `new_with_backup()`, `is_backup` flag |

### 1.5 Connection Lifecycle

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Target Resolution | **VERIFIED** | `src/router.rs:1124-1219` | `Router::route()` and `route_to_target()` |
| Lease | **VERIFIED** | `src/upstream/pool.rs:301-304` | `connection_scope()` returns `ConnectionGuard` |
| Protocol Negotiation | **NOT IN CODE** | N/A | No explicit connection lease concept; uses HTTP keepalive via hyper |
| Execution | **VERIFIED** | Various backend handlers | Proxy handlers in `src/http/server.rs` |
| Release | **VERIFIED** | `src/upstream/pool.rs:172-176` | `ConnectionGuard::drop()` calls `decrement_connections()` |

---

## 2. Improvement Plan

### HIGH Priority

1. **Document Missing Backend Types**
   - `AxumDynamic`, `Spin`, `Cgi`, `PeakEwma` are implemented but not documented
   - Location: `src/router.rs:65-77`, `src/upstream/pool.rs:48-56`

2. **Active Health Checks for UpstreamPool**
   - Only `FastCgiPool` has active health checks; `UpstreamPool` relies only on passive
   - `src/fastcgi/pool.rs:148` vs `src/upstream/pool.rs` (no active check thread)
   - Add periodic health check thread to `UpstreamPool`

3. **`current_depth()` Always Returns 0 - Dead Code**
   - `src/location_matcher.rs:191-195`
   - The `current_depth()` function is a stub that always returns 0
   - `find_best_match()` at line 177 calls this but result is unused correctly due to the bug

### MEDIUM Priority

4. **Update Document for Connection Lifecycle**
   - Step 3 "Protocol Negotiation" doesn't match actual implementation
   - No explicit lease mechanism; HTTP/1.1 keepalive handled by hyper client
   - Consider removing or rephrasing "Lease" step

5. **Weighted Round Robin Not Exposed in Config**
   - Algorithm exists at `src/upstream/pool.rs:566-583` but may not be configurable via site config
   - No `LoadBalanceAlgorithm` serialization found

6. **LocationMatcher Trie Implementation Incomplete**
   - `TrieNode::find_best_match()` at `src/location_matcher.rs:139-188` has complex logic
   - `current_depth()` stub suggests incomplete migration from original strategy
   - The fallback matching at lines 262-263 uses simple iteration, not trie

### LOW Priority

7. **Document Spin Backend**
   - `BackendType::Spin` at `src/router.rs:76` not documented

8. **Add IP Hash Algorithm Description**
   - Document mentions IP Hash but doesn't explain how it works

---

## 3. Bug Reports

### CRITICAL

1. **`current_depth()` Always Returns 0 - Potential Logic Error**
   - **File**: `src/location_matcher.rs:191-195`
   - **Issue**: `fn current_depth(node: *const TrieNode, root: *const TrieNode) -> usize { 0 }`
   - **Impact**: The function is a stub. However, in `find_best_match()` at line 177, it's only used in a condition that appears to check exact depth matching for path traversal. If `current_depth()` returned a real value, it would affect the exact match detection logic at lines 179-185.
   - **Code using it**:
     ```rust
     || path.split('/').filter(|s| !s.is_empty()).count() == current_depth(current, self);
     ```
   - **Risk**: If the trie matching path is ever used instead of the fallback iteration path (lines 242-263), this could cause incorrect route matching.

### MINOR

2. **Document Omission - Backend Types**
   - Not a bug, but documentation drift: `AxumDynamic`, `Spin`, `Cgi`, `PeakEwma` exist in code but not in architecture doc

3. **Commented Code Path in `current_depth()`**
   - `src/location_matcher.rs:192-193`: "This is a bit complex to implement correctly without parent pointers. Let's simplify the Trie to use a different matching strategy."
   - This suggests an abandoned implementation approach

4. **Missing Algorithm Configuration Documentation**
   - `LoadBalanceAlgorithm::WeightedRoundRobin` exists but may not be configurable, unclear from doc

---

## Summary

| Category | Count |
|----------|-------|
| Verified Claims | 18 |
| Partial Claims | 1 |
| Unverified Claims | 0 |
| Missing from Docs (found in code) | 5 |
| High Priority Improvements | 3 |
| Medium Priority Improvements | 3 |
| Low Priority Improvements | 2 |
| Critical Bugs | 1 |
| Minor Issues | 3 |

**Overall Assessment**: The routing architecture document is largely accurate and well-aligned with the implementation. Main gaps are missing backend types (Spin, AxumDynamic, Cgi, PeakEwma) and the incomplete active health check system for upstream pools. The `current_depth()` stub represents a latent bug risk but is not currently triggered.
