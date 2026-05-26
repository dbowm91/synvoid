# Routing Module Review Plan

## Verified Correct Items

1. **BackendType enum variants** - All 11 variants listed in the document exist in `src/router.rs:65-78`:
   - Upstream, FastCgi, Php, Cgi, Static, AppServer, AxumDynamic, Spin, Serverless, Mesh, QuicTunnel

2. **Reverse-domain Radix tree implementation** - The `reverse_domain_for_router()` function exists at `src/router.rs:1377-1381` and correctly reverses domains for wildcard/suffix matching.

3. **LocationMatcher path-based matching** - The `LocationMatcher` struct in `src/location_matcher.rs` correctly handles path-based routing with support for Exact, PreferentialPrefix, Regex, and Prefix match types.

4. **parse_quictunnel_url() function** - Located at `src/router.rs:512-532`, correctly parses quictunnel:// URLs.

5. **LoadBalanceAlgorithm enum** - Contains all 6 algorithms at `src/upstream/pool.rs:48-57`: RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash.

6. **PeakEwma formula** - Document states `(conn + 1) * (latency + 1)` which matches implementation at `src/upstream/pool.rs:517-526`.

7. **Connection lifecycle methods** - `increment_connections()` and `decrement_connections()` exist in `src/upstream/pool.rs:287-295`.

8. **BackendType ordering** - The document lists "Spin" before "Serverless (WASM)", which matches the enum order in `src/router.rs:65-78`.

---

## Stale/Incorrect Items

1. **Line reference for parse_quictunnel_url()** (routing_deep_dive.md:49)
   - **Claim**: `Router::parse_quictunnel_url()` at lines 513-532
   - **Actual**: Function exists at lines 512-532 (correct line numbers, but documentation should use local paths not GitHub URLs)

2. **LoadBalanceAlgorithm line reference** (routing_deep_dive.md:64)
   - **Claim**: References `src/upstream/pool.rs:48-57`
   - **Actual**: The `LoadBalanceAlgorithm` enum is at lines 48-57, but `PeakEwma` formula/usage is at lines 513-528. The reference is partially correct but misleading since it suggests the formula is at 48-57.

3. **src/routing/ directory** (throughout document context)
   - **Issue**: Document implies existence of `src/routing/` directory for routing-related code
   - **Actual**: All routing code is in `src/router.rs`, `src/location_matcher.rs`, `src/upstream/pool.rs` - there is no `src/routing/` subdirectory

---

## Bugs Found

None identified - the routing implementation appears consistent with the architecture document.

---

## Security Concerns

1. **No security issues found** in the routing architecture itself.
   - Domain matching is case-insensitive via `clean_domain()` at line 476
   - URL validation in `validate_upstream_url()` at `src/upstream/pool.rs:14-46` blocks unsafe schemes (file://, ftp://, gopher://)
   - Regex complexity checking in `LocationMatcher` prevents ReDoS attacks

---

## Document Update Recommendations

1. **Replace GitHub URLs with local paths** (routing_deep_dive.md:49, 64)
   - Change: `[Router::parse_quictunnel_url()](https://github.com/synvoid/synvoid/blob/main/src/router.rs#L513-L532)`
   - To: `Router::parse_quictunnel_url()` at `src/router.rs:512-532`
   - Change: `[src/upstream/pool.rs:48-57]` to `src/upstream/pool.rs:48-57`

2. **Add clarification on matching hierarchy order** (routing_deep_dive.md:9-15)
   - Current text correctly describes the matching flow but could benefit from noting that listener-level default is only consulted as a final fallback after global matching fails

3. **Clarify src/routing/ does not exist** or reorganize documentation structure
   - Consider either:
     a. Documenting the actual file structure (router.rs, location_matcher.rs, upstream/pool.rs)
     b. Or noting that "routing" is a conceptual grouping, not a filesystem directory

4. **Update line reference for PeakEwma formula** (routing_deep_dive.md:64)
   - Consider adding a second reference: "formula at `src/upstream/pool.rs:517-521`" to point readers directly to the cost calculation
