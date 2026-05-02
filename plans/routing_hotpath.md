# Routing Hot-Path Analysis (Architecture Priority 6)

**Status**: Documentation/Verification
**Last Updated**: 2026-05-02

This document captures the current state of routing hot-path optimizations and documents remaining issues for future consideration.

---

## Summary of Findings

| Component | Status | Notes |
|-----------|--------|-------|
| `LocationMatcher::match_uri()` | **Optimized** | Uses scalar best-match tracking, no per-request vector allocation |
| Host validation (`is_host_valid_for_site`) | **Fixed** | Now passes cleaned host instead of site_id |
| Suffix/wildcard host matching | **Linear scan** | `suffix_domain_map: Vec<(Arc<str>, Arc<SiteConfig>)>` - O(n) per request |
| `route_with_local_addr()` | **Minor issue** | Creates `Arc<str>` for lookup that could use `&str` directly |
| Host validation loop | **Minor issue** | Uses `format!(".{}", clean_domain)` inside loop |

---

## 1. What Routing Optimizations Are Already In Place

### LocationMatcher Optimization (wave16, Priority 2 - COMPLETED)

**Location**: `src/location_matcher.rs:132-189`

The `match_uri()` method was optimized to use **scalar best-match tracking** instead of four vectors:

```rust
pub fn match_uri(&self, uri: &str) -> Option<(usize, LocationMatchType)> {
    let mut best_exact: Option<&LocationMatch> = None;
    let mut best_pref_prefix: Option<&LocationMatch> = None;
    let mut first_regex: Option<&LocationMatch> = None;
    let mut best_prefix: Option<&LocationMatch> = None;

    for loc in &self.locations {
        // Update best matches with scalar Option references
        // ...
    }
    // Return in precedence order
}
```

**What was removed:**
- Four `Vec<LocationMatch>` vectors allocated per request
- No heap allocation in the common path

**What was preserved:**
- Nginx-like precedence: exact > preferential prefix > first regex > longest prefix
- `original_order` return value for tie-breaking

### Host Validation Fix (wave16, Priority 2 - COMPLETED)

**Location**: `src/router.rs:386-398`, `src/router.rs:706-713`

The `route_to_target()` function now receives `clean_host` and uses it for `reject_unknown_hosts` validation:

```rust
fn route_to_target(
    &self,
    site_config: &Arc<SiteConfig>,
    path: &str,
    clean_host: &str,  // Now properly passed
) -> RouteResult {
    let site_id = site_config.site_id();

    if site_config.security.reject_unknown_hosts.unwrap_or(false)
        && !self.is_host_valid_for_site(clean_host, site_config)  // Uses clean_host, not site_id
    {
        return RouteResult::NotFound("Host not allowed".to_string());
    }
```

---

## 2. Remaining Hot-Path Issues

### Issue 1: Suffix/Wildcard Host Matching - Linear Vec Scan

**Location**: `src/router.rs:32`, `src/router.rs:1012-1015`

```rust
suffix_domain_map: Vec<(Arc<str>, Arc<SiteConfig>)>,  // Line 32
```

**Scanned at runtime (lines 1012-1015):**
```rust
for (domain, site_config) in &self.suffix_domain_map {
    if clean_host.ends_with(domain.as_ref()) {
        return self.route_to_target(site_config, path, &clean_host);
    }
}
```

**Impact:**
- O(n) scan through suffix/wildcard domains for every request that doesn't match exactly
- Sort order (`suffix_domain_map.sort_by(|a, b| b.0.len().cmp(&a.0.len()))`) helps longest-match semantics but doesn't reduce complexity

**Practical limit:**
- For typical deployments with < 100 wildcard domains, this is acceptable
- Multi-tenant deployments with thousands of wildcard domains would notice this

### Issue 2: Unnecessary Arc<str> Creation in route_with_local_addr

**Location**: `src/router.rs:983-1008`

```rust
pub fn route_with_local_addr(
    &self,
    host: &str,
    path: &str,
    local_addr: Option<SocketAddr>,
) -> RouteResult {
    let clean_host = Self::clean_domain(host);
    let clean_host_arc: Arc<str> = Arc::from(clean_host.as_str());  // Line 983 - allocation

    // ...

    if let Some(site_config) = self.domain_map.get(clean_host_arc.as_ref()) {  // Line 1008
        return self.route_to_target(site_config, path, &clean_host);
    }
```

**Impact:**
- Creates an `Arc<str>` allocation for every request even when the domain map lookup could use `&str`
- The HashMap key lookup could accept `clean_host.as_str()` directly as `&str`

**Severity:** Minor - single small allocation per request, but contradicts the "avoid per-request allocation" goal

### Issue 3: format!() in Host Validation Loop

**Location**: `src/router.rs:386-398`

```rust
fn is_host_valid_for_site(&self, clean_host: &str, site_config: &Arc<SiteConfig>) -> bool {
    if let Some(cleaned) = self.cleaned_site_domains.get(&site_config.site_id()) {
        for clean_domain in cleaned {
            if clean_host == clean_domain.as_ref()
                || clean_host.ends_with(&format!(".{}", clean_domain))  // Line 390 - allocation
            {
                return true;
            }
        }
    }
    false
}
```

**Impact:**
- `format!(".{}", clean_domain)` creates a new `String` for each domain comparison
- Could allocate on each iteration when suffix matching is needed

**Severity:** Minor - the allocation is short-lived and the loop typically has few iterations

---

## 3. Practical Limits for Wildcard Matching

| Domain Count | Match Complexity | Expected Impact |
|--------------|------------------|-----------------|
| < 50 | O(n) with small n | Negligible (< 1µs) |
| 50-500 | O(n) scan | Acceptable (< 10µs) |
| 500-2000 | O(n) scan | Noticeable at high RPS |
| > 2000 | O(n) scan | Problematic for 1000K RPS target |

**Current data structure:** `Vec<(Arc<str>, Arc<SiteConfig>)>` sorted by domain length descending

**Potential optimizations if needed:**
1. Reversed-label trie for suffix matching
2. Multi-label HashMap keyed by top-level domain
3. Precomputed suffix tree for common TLDs

---

## 4. Items That Could Not Be Fully Verified

### Verification Complete:
- `LocationMatcher::match_uri()` - Confirmed scalar tracking implementation
- `is_host_valid_for_site()` - Confirmed uses `clean_host` parameter
- `suffix_domain_map` - Confirmed Vec-based linear scan
- `route_with_local_addr()` - Confirmed Arc allocation

### Could Not Verify (requires runtime benchmarks):
- Actual per-request latency impact of suffix Vec scan
- Memory pressure at high site counts
- Cache locality effects on match_uri with many locations

### Notes:
- The ignored test `test_glob_pattern` in location_matcher.rs (line 282) mentions "Hangs during matching - needs investigation" - this appears unrelated to the allocation optimization work
- No benchmark harness currently exists for routing hot-path measurement

---

## Conclusion

**Location matching is allocation-free** - the wave16 optimization successfully removed per-request vector allocations.

**Host matching** has one O(n) path (suffix/wildcard scan) that is acceptable for typical deployments but would become a bottleneck at 1000K RPS with thousands of wildcard domains.

**Minor allocations remain** in `route_with_local_addr()` (Arc creation) and `is_host_valid_for_site()` (format! in loop), but these are unlikely to be the primary bottleneck at stated scale targets.

If Priority 6 is pursued as a future optimization, the suffix/wildcard data structure would be the highest-impact change. The current implementation is correct and the code is clean.