# Routing Architecture Review Plan

## Verified Correct Items

1. **BackendType enum** - All 11 variants (Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin) correctly listed in doc at `src/router.rs:65-78` ✅

2. **Radix tree wildcard matching** - Reverse-domain pattern correctly documented (`foo.bar.example.com` → `/foo/bar/example/com`) ✅

3. **parse_quictunnel_url function** - Located at `src/router.rs:513` (line number matches doc) ✅

4. **PeakEwma load balancing formula** - `(conn + 1) * (latency + 1)` correctly documented at `src/upstream/pool.rs:520-521` ✅

5. **Matching hierarchy** - Implementation matches documentation (IP-based → listener default → exact domain → wildcard/suffix → default fallback → path-based) ✅

---

## Discrepancies Found

### D1: Incorrect Line Reference for Field Definitions

**Doc states:** `ip_domain_map` at `src/router.rs:42` and `ip_wildcard_routers` at `src/router.rs:43`

**Actual:** Line 42-43 are in the `Router` struct body:
```rust
ip_domain_map: HashMap<(SocketAddr, Arc<str>), Arc<SiteConfig>>,  // line 42
ip_wildcard_routers: HashMap<SocketAddr, Arc<MatchRouter<Arc<SiteConfig>>>>,  // line 43
```

The `SiteMaps` type alias containing the same fields is at lines 52-63.

**Severity:** Low (documentation accuracy issue)

---

### D2: BUG-ROUTER-1 Line Reference is Incorrect

**AGENTS.md states:** BUG-ROUTER-1 is at `src/router.rs:1318`

**Analysis:**
- `update_sites` method (lines 1223-1375) correctly uses `server_port` parameter
- `build_listen_map_entry` (lines 396-436) uses `main_config.server.port`
- `build_ip_domain_maps` (lines 349-394) uses `main_config.server.port`

The bug was likely in an earlier version. Current code appears correct.

**Severity:** Low (AGENTS.md line reference stale)

---

### D3: Default Implementation Has Hardcoded 80

**Location:** `src/router.rs:1420` in `Default` impl:
```rust
server_port: 80,
```

This is acceptable for `Default` trait, but worth noting.

**Severity:** Informational

---

## Bugs Identified

### BUG-R2: Inconsistent Port Resolution Between Methods

**Location:** `src/router.rs:403` vs `src/router.rs:1320`

- `build_listen_map_entry` uses `main_config.server.port` (line 403)
- `update_sites` uses `server_port` parameter (line 1320)

While both ultimately use configured port (not hardcoded 80), the inconsistency suggests `update_sites` was the bug fix location.

**Severity:** Low (no functional bug currently, but inconsistent pattern)

---

## Suggested Improvements

### IMP-1: Add Inline Documentation to Routing Steps

The matching hierarchy is well-documented in the arch doc but not in code. Add rustdoc comments to `route_with_local_addr` explaining each step.

### IMP-2: Add Test Coverage for Wildcard Domain Matching

Verify the radix tree correctly handles:
- `*.example.com` matching `foo.example.com` (subdomain)
- `example.com` exact match
- `com` suffix match for `example.com`

### IMP-3: Update AGENTS.md Line Reference

Update BUG-ROUTER-1 reference from `src/router.rs:1318` to the correct method (`update_sites` at line 1223 or the specific port resolution logic).

### IMP-4: Consider Consolidating Port Resolution

Both `build_listen_map_entry` and `build_ip_domain_maps` use identical port resolution logic:
```rust
let http_port = if listen_config.is_ssl() {
    main_config.tls.port
} else {
    main_config.server.port
};
```

Consider extracting to a helper method on `SiteListenConfig`.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 5 |
| Discrepancies | 3 |
| Bugs | 1 (low severity) |
| Improvements | 4 |

The routing architecture implementation largely matches the documentation. The main concern is stale line references in AGENTS.md and minor documentation inaccuracies.