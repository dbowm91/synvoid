# Reverse Proxy & WAF Security & Scalability Improvement Plan

**Plan ID**: 18
**Date**: 2026-04-23
**Status**: Draft
**Priority**: Critical (Security & Performance)

---

## Executive Summary

Comprehensive review of the reverse proxy and WAF architecture identified critical security vulnerabilities and scalability bottlenecks. The unified worker handles all HTTP/HTTPS + WAF + mesh routing in a single async process designed for 500K+ requests/second.

### Critical Findings Summary

| Category | # | Issue | Severity | Status |
|----------|---|-------|----------|--------|
| Security | 1 | TLS Passthrough WAF Bypass | **CRITICAL** | Fix Required |
| Security | 2 | HS256/RS256 Algorithm Confusion (JWT) | **HIGH** | Fix Required |
| Security | 3 | IPv4-Mapped IPv6 SSRF Bypass | **HIGH** | Fix Required |
| Security | 4 | DNS Rebinding SSRF Attack | **HIGH** | Fix Required |
| Performance | 5 | Per-Request DHT Threat Lookup | **HIGH** | Fix Required |
| Scalability | 6 | Connection Pool Limits Hardcoded | **HIGH** | Fix Required |
| Reliability | 7 | Global Rate Limiter Blackhole False Positives | **MEDIUM** | Fix Required |
| Performance | 8 | GeoIP ASN Lookup Lock Contention | **MEDIUM** | Fix Required |
| Code Quality | 9 | LRU Rate Limiter Eviction Non-Functional | **LOW** | Cleanup |
| Security | 10 | Double URL Decoding Depth Limit | **LOW** | Document |
| **Security** | **11** | **CRLF Injection** | **GOOD** | **No Action - Well Protected** |
| **Code Quality** | **12** | **Per-Site Upstream Connection Isolation** | **LOW** | **Enhancement** |

---

## User Requirements

### TLS Passthrough Policy

- **Opt-in only**: Sites must explicitly enable `tls_passthrough = true`
- **WAF required for security**: `tls_passthrough_enforce_waf = true` should be the recommended setting
- **Aggressive warnings**: Log ERROR (not WARN) when TLS passthrough bypasses WAF
- **Rate limiting minimum**: When TLS passthrough is active, rate limiting MUST be enforced at minimum

### DNS Resolution for SSRF

- **Primary**: Use own global recursive DNS nodes (if deployed in mesh mode)
- **Fallback**: Use configured third-party DNS (e.g., 1.1.1.1, 8.8.8.8)
- **Local caching**: Implement DNS response caching with appropriate TTL
- **Mesh-aware**: If mesh deployment has recursive DNS capability, use it for SSRF lookups

---

## Phase 1: Critical Security Fixes

### 1.1 TLS Passthrough WAF Bypass Fix

**Issue**: `tls_passthrough_enforce_waf` only logs warnings, does not enforce. `proxy_raw_tcp()` is defined but not wired into request handling. Sites with TLS passthrough bypass ALL WAF inspection.

**User Decision**: TLS passthrough must be opt-in with aggressive warnings. Minimum requirement: rate limiting must be enforced.

#### Implementation Requirements

**File**: `src/worker/unified_server.rs`

```rust
// Change WARN to ERROR for TLS passthrough bypass
tracing::error!(
    "CRITICAL SECURITY: TLS passthrough is enabled for sites: {:?}. \
    WAF inspection is BYPASSED - L7 attacks (SQL injection, XSS, etc.) will NOT be blocked. \
    This is a severe security risk for production environments. \
    Set tls_passthrough_enforce_waf = true OR disable tls_passthrough.",
    bypass_sites
);
```

**File**: `src/config/site/proxy.rs`

```rust
// Make tls_passthrough default to false (opt-in)
#[serde(default)]
pub tls_passthrough: Option<bool>,  // None = disabled by default

// Add validation: if tls_passthrough = true AND waf is enabled, require enforce_waf
```

**File**: `src/tls/server.rs`

```rust
// Wire proxy_raw_tcp() into request handling IF configured
// But ensure rate limiting is ALWAYS active for passthrough traffic
```

**Configuration Example**:
```toml
# WRONG - bypasses WAF (should require explicit acknowledgment)
[site.mysite]
proxy.tls_passthrough = true

# CORRECT - enables TLS passthrough WITH WAF inspection
[site.mysite]
proxy.tls_passthrough = true
proxy.tls_passthrough_enforce_waf = true

# RECOMMENDED - disable TLS passthrough for security
[site.mysite]
proxy.upstream.url = "https://origin.example.com"
# No tls_passthrough = full WAF protection
```

**Rate Limiting Enforcement**:
- When `tls_passthrough = true`, rate limiting MUST be active
- Log warning if rate limiting is disabled for passthrough sites
- Consider additional connection limiting for passthrough sites

**Effort**: Medium
**Risk**: Low (defensive improvements)
**Status**: Pending

---

### 1.2 HS256/RS256 Algorithm Confusion Attack Fix (JWT)

**Issue**: The JWT detector is pattern-based only. Cannot detect classic algorithm confusion attack where attacker changes `alg` from RS256 to HS256 and forges using the public key as HMAC secret.

**Reference**: Auth0 Research - "Critical vulnerabilities in JSON Web Token libraries" (2015)

#### Implementation Requirements

**File**: `src/waf/attack_detection/jwt.rs`

```rust
// Add to SAFE_JWT_ALGORITHMS configuration
const SAFE_JWT_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA",  // Ed25519 signature algorithm
];

// Add algorithm family tracking
const ASYMMETRIC_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA",
];

const SYMMETRIC_ALGS: &[&str] = &[
    "HS256", "HS384", "HS512",
];

// New detection function
fn check_algorithm_confusion(&self, header: &str, expected_alg: Option<&str>) -> Option<AttackDetectionResult> {
    if let Ok(header_json) = serde_json::from_str::<Value>(header) {
        if let Some(alg) = header_json.get("alg").and_then(|v| v.as_str()) {
            // Check for symmetric→asymmetric or asymmetric→symmetric switch
            let is_asymmetric = ASYMMETRIC_ALGS.iter().any(|&a| a.eq_ignore_ascii_case(alg));
            let is_symmetric = SYMMETRIC_ALGS.iter().any(|&a| a.eq_ignore_ascii_case(alg));

            if let Some(expected) = expected_alg {
                let expected_is_asymmetric = ASYMMETRIC_ALGS.iter().any(|&a| a.eq_ignore_ascii_case(expected));

                // Block algorithm family switch
                if expected_is_asymmetric && is_symmetric {
                    return Some(AttackDetectionResult {
                        attack_type: AttackType::JwtAlgorithmConfusion,
                        // ...
                    });
                }
            }
        }
    }
    None
}
```

**Configuration Option**:
```toml
# In WAF config
[waf.jwt]
# Expected algorithm for JWT validation (if known)
expected_algorithm = "RS256"
# Block HS256 algorithm entirely (for high security)
block_hs256 = false
```

**Note**: Full cryptographic signature verification would require adding `jsonwebtoken` crate. This pattern-based check provides immediate protection against algorithm confusion without adding dependency.

**Effort**: Medium
**Risk**: Low
**Status**: Pending

---

### 1.3 IPv4-Mapped IPv6 SSRF Bypass Fix

**Issue**: `::ffff:192.168.1.1` is NOT detected as private IP, but `192.168.1.1` IS. IPv4-mapped IPv6 addresses bypass private IP detection.

#### Implementation Requirements

**File**: `src/waf/attack_detection/ssrf.rs:132-150`

```rust
// Current code (incomplete):
IpAddr::V6(v6) => {
    let segments = v6.segments();
    segments[0] == 0xFE80
        || (segments[0] & 0xFE80) == 0xFC00
        || segments[0] == 0xFF00
        || segments == [0, 0, 0, 0, 0, 0, 0, 1]  // Only ::1 checked
}

// FIX:
IpAddr::V6(v6) => {
    let segments = v6.segments();

    // Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    // Structure: ::ffff:<4 bytes IPv4>
    if segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
        && segments[4] == 0 && segments[5] == 0xffff
    {
        // Extract IPv4 address from segments[6] and segments[7]
        let ipv4_addr = format!(
            "{}.{}.{}.{}",
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8
        );
        // Recursively check if IPv4 is private
        return Self::check_is_private_ipv4(&ipv4_addr);
    }

    // Existing checks
    segments[0] == 0xFE80  // Link-local
        || (segments[0] & 0xFE80) == 0xFC00  // Unique local
        || segments[0] == 0xFF00  // Multicast
        || segments == [0, 0, 0, 0, 0, 0, 0, 1]  // ::1 loopback
}
```

**Test Cases Required**:
```rust
#[test]
fn test_ssrf_ipv4_mapped_ipv6_bypass() {
    let detector = SsrfDetector::new(/* config */);
    // These should ALL be blocked:
    assert!(detector.detect("http://[::ffff:192.168.1.1]/admin", InputLocation::QueryString).is_some());
    assert!(detector.detect("http://[::ffff:10.0.0.1]/admin", InputLocation::QueryString).is_some());
    assert!(detector.detect("http://[::ffff:172.16.0.1]/admin", InputLocation::QueryString).is_some());
    assert!(detector.detect("http://[::ffff:127.0.0.1]/admin", InputLocation::QueryString).is_some());
}
```

**Effort**: Low
**Risk**: Low
**Status**: Pending

---

### 1.4 DNS Rebinding SSRF Protection

**Issue**: SSRF detector does NOT perform DNS resolution. Attacker can register `evil.com` → public IP, pass WAF, then change DNS to point to `127.0.0.1`.

**User Decision**: Use own global recursive DNS nodes (mesh deployment), local caching, or third-party fallback.

#### Implementation Requirements

**Architecture**:
```
SSRF Detection
    │
    ├─── Mesh Mode ───────────► Use Global Recursive DNS Nodes
    │                              (via mesh/dns_recursive)
    │
    ├─── Non-Mesh Mode ──────► Use Configured Third-Party DNS
    │                              (1.1.1.1, 8.8.8.8, etc.)
    │
    └─── Local Cache ─────────► Cache DNS responses with TTL
                                   (prevents DNS rebinding race)
```

**File**: `src/waf/attack_detection/ssrf.rs`

```rust
// Add DNS resolver capability to SsrfDetector
pub struct SsrfDetector {
    // ... existing fields
    dns_resolver: Option<Arc<DnsResolver>>,
    dns_cache: MokaCache<String, DnsResolutionResult>,
}

impl SsrfDetector {
    // New method for DNS resolution
    fn check_domain_resolution(&self, domain: &str) -> Option<AttackDetectionResult> {
        // Check cache first
        if let Some(cached) = self.dns_cache.get(domain) {
            if cached.is_private_ip() {
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Ssrf,
                    fingerprint: Some("dns_rebinding_detected".to_string()),
                    // ...
                });
            }
            return None; // Cached, public, allowed
        }

        // Resolve DNS
        let resolution = match &self.dns_resolver {
            Some(resolver) => resolver.resolve(domain),
            None => self.fallback_dns_resolution(domain),
        };

        // Cache result
        self.dns_cache.insert(domain.to_string(), resolution.clone());

        // Check resolved IP
        if resolution.is_private_ip() {
            return Some(AttackDetectionResult {
                attack_type: AttackType::Ssrf,
                fingerprint: Some("dns_rebinding_to_private".to_string()),
                // ...
            });
        }

        None
    }
}

// DNS resolution strategies
enum DnsResolutionStrategy {
    // Use mesh global recursive DNS nodes
    MeshRecursive,
    // Use third-party (1.1.1.1, 8.8.8.8)
    ThirdParty(Vec<String>),
    // No resolution (legacy mode)
    Disabled,
}
```

**Configuration**:
```toml
# In WAF config for SSRF
[waf.ssrf]
# Enable DNS resolution for SSRF detection
dns_resolution_enabled = true

# Resolution strategy
# "mesh" = use global recursive DNS nodes (if mesh deployment)
# "third_party" = use specified DNS servers
dns_resolution_strategy = "mesh"

# Third-party DNS fallback (if mesh unavailable or strategy = "third_party")
fallback_dns_servers = ["1.1.1.1:53", "8.8.8.8:53"]

# DNS cache TTL in seconds (default: 60)
dns_cache_ttl_secs = 60

# Only perform DNS resolution in allowlist-only mode (recommended)
# This avoids performance impact for non-allowlisted domains
allowlist_only_mode = true
```

**Mesh Integration**:
```rust
// In unified_server.rs initialization
let dns_resolver = if mesh_mode {
    // Use mesh global recursive DNS
    Some(Arc::new(MeshDnsResolver::new(mesh_transport.clone())))
} else {
    // Use third-party DNS
    Some(Arc::new(ThirdPartyDnsResolver::new(config.dns_servers.clone())))
};
```

**Effort**: High
**Risk**: Medium
**Status**: Pending

---

## Phase 2: Performance Critical Fixes

### 2.1 Per-Request DHT Threat Lookup Cache

**Issue**: Every request may trigger DHT lookup with:
- Full `record_state.read()` RwLock acquisition (serializes ALL DHT lookups)
- JSON parsing allocation per request
- No dedicated cache for threat lookups

#### Implementation Requirements

**File**: `src/mesh/threat_intel.rs`

```rust
// Add to ThreatIntelligenceManager
use moka::sync::Cache;

pub struct ThreatIntelligenceManager {
    // ... existing fields
    threat_indicator_cache: Cache<String, CachedThreatIndicator>,
}

struct CachedThreatIndicator {
    indicator: ThreatIndicator,
    expires_at: u64,
}

impl ThreatIntelligenceManager {
    // Replace lookup_threat_indicator_in_dht with cached version
    pub fn lookup_threat_indicator_cached(&self, ip: &str, threat_type: ThreatType) -> Option<ThreatIndicator> {
        let cache_key = format!("threat_indicator:{}:{:?}", ip, threat_type);

        // Check cache first
        if let Some(cached) = self.threat_indicator_cache.get(&cache_key) {
            if cached.expires_at > current_timestamp() {
                return Some(cached.indicator.clone());
            }
            // Expired - invalidate
            self.threat_indicator_cache.remove(&cache_key);
        }

        // Cache miss - query DHT
        if let Some(indicator) = self.lookup_threat_indicator_in_dht(ip, threat_type) {
            // Cache with TTL from indicator or default 60s
            let ttl = indicator.ttl_seconds.unwrap_or(60);
            self.threat_indicator_cache.insert(cache_key, CachedThreatIndicator {
                indicator: indicator.clone(),
                expires_at: current_timestamp() + ttl,
            });
            return Some(indicator);
        }

        None
    }
}
```

**Configuration**:
```toml
# In mesh config
[mesh.threat_intel]
# Cache threat indicators for performance
threat_lookup_cache_size = 10000
threat_lookup_cache_ttl_secs = 60
```

**Effort**: Medium
**Risk**: Low
**Status**: Pending

---

### 2.2 Connection Pool Limits Configurable

**Issue**: `max_connections=100` hardcoded, `pool_max_idle_per_host=100` hardcoded, `pool_idle_timeout=30s` hardcoded. Not exposed via site proxy config.

#### Implementation Requirements

**File**: `src/config/site/proxy.rs`

```rust
pub struct ProxyUpstreamConfig {
    // ... existing fields

    // NEW: Connection pool configuration
    #[serde(default)]
    pub max_connections: Option<usize>,        // Backend max connections

    #[serde(default)]
    pub pool_max_idle_per_host: Option<usize>, // HTTP client pool max idle

    #[serde(default)]
    pub pool_idle_timeout_secs: Option<u64>,   // HTTP client pool idle timeout

    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,     // Connection timeout
}
```

**File**: `src/proxy/mod.rs`

```rust
// Apply configuration to upstream pool
fn create_upstream_pool(config: &ProxyUpstreamConfig) -> UpstreamPool {
    let mut pool = UpstreamPool::new();

    // Apply connection limits
    if let Some(max_conn) = config.max_connections {
        pool.set_max_connections(max_conn);
    }

    // Add backends with configured limits
    for server in &config.servers {
        let backend = Backend::new(server)
            .with_max_connections(config.max_connections.unwrap_or(100));
        pool.add_backend(backend);
    }

    pool
}
```

**File**: `src/http_client/mod.rs`

```rust
// Add configuration to HTTP client creation
pub fn create_upstream_client_with_config(
    config: &ProxyUpstreamConfig,
) -> HttpClient {
    let pool_max_idle = config.pool_max_idle_per_host.unwrap_or(100);
    let pool_idle_timeout = Duration::from_secs(config.pool_idle_timeout_secs.unwrap_or(30));
    let connect_timeout = Duration::from_secs(config.connect_timeout_secs.unwrap_or(5));

    // ... existing client creation with custom config
}
```

**Configuration**:
```toml
# In site proxy config
[site.high_traffic_site.proxy.upstream]
url = "http://backend1:8000"

# Connection pool tuning for high traffic
max_connections = 10000
pool_max_idle_per_host = 1000
pool_idle_timeout_secs = 120
connect_timeout_secs = 10
```

**Effort**: Medium
**Risk**: Low
**Status**: Pending

---

## Phase 3: Reliability Fixes

### 3.1 Global Rate Limiter Blackhole - Per-IP Tracking

**Issue**: Blackhole is global (not per-IP). One loud neighbor blackholes everyone. No manual override exists.

#### Implementation Requirements

**File**: `src/waf/ratelimit/core.rs`

```rust
// Add per-IP blackhole tracking
pub struct GlobalRateLimiter {
    // ... existing fields
    ip_blackhole_state: RwLock<HashMap<IpAddr, IpBlackholeState>>,
    ip_blackhole_max_entries: usize,  // Limit tracking to prevent memory exhaustion
}

struct IpBlackholeState {
    blackholed_at: u64,
    probe_backoff_secs: u64,
    consecutive_low_samples: u32,
}

// Modify check_and_increment to track per-IP
pub fn check_and_increment(&self, ip: IpAddr) -> RateLimitDecision {
    // Check if this specific IP is blackholed
    if let Some(ip_state) = self.ip_blackhole_state.read().get(&ip) {
        if self.should_blackhole_ip(ip_state) {
            return RateLimitDecision::Blackholed;
        }
    }

    // ... existing global checks
}

// Add admin API for blackhole reset
pub fn reset_ip_blackhole(&self, ip: IpAddr) {
    self.ip_blackhole_state.write().remove(&ip);
}

pub fn reset_all_blackholes(&self) {
    self.ip_blackhole_state.write().clear();
}
```

**Admin API Endpoint**:
```rust
// In admin API
DELETE /api/v1/ratelimit/blackhole/{ip}  // Reset single IP
DELETE /api/v1/ratelimit/blackhole       // Reset all
GET    /api/v1/ratelimit/blackhole       // List current blackholed IPs
```

**Effort**: High
**Risk**: Medium
**Status**: Pending

---

### 3.2 GeoIP ASN Lookup - Increase Cache Size

**Issue**: Default 10,000 entry cache may cause thrashing with diverse client IPs at 500K rps.

#### Implementation Requirements

**File**: `src/config/defaults.rs`

```rust
// Current: 10,000
// Recommended: 100,000 for high-traffic deployments

pub const DEFAULT_ASN_CACHE_SIZE: usize = 100_000;
```

**File**: `src/waf/asn_tracker.rs`

```rust
// Add metrics for cache hit rate
pub fn get_cache_stats(&self) -> AsnCacheStats {
    AsnCacheStats {
        size: self.asn_cache.len(),
        capacity: self.asn_cache.capacity(),
        // Note: moka doesn't expose hit rate directly
        // Could add instrumentation via custom counter
    }
}
```

**Configuration**:
```toml
# In WAF config
[waf.asn_tracking]
enabled = true
cache_size = 100000  # Increase from default
```

**Effort**: Low
**Risk**: None
**Status**: Pending

---

## Phase 4: Code Quality

### 4.1 LRU Rate Limiter Eviction - Remove Dead Code

**Issue**: The `lru_order` and `ip_requests` HashMaps in rate limiter are never populated. LRU eviction is a no-op. All rate limiting happens via `SlottedIpRateLimiter`.

#### Implementation Requirements

**File**: `src/waf/ratelimit.rs`

```rust
// Option A: Remove dead code
// Remove lru_order, ip_requests, and evict_lru_entries() if never used

// Option B: Fix the LRU population (if desired for future use)
// Populate lru_order during check_rate_limit()

// Recommendation: Option A (remove dead code) for now
// The SlottedIpRateLimiter handles all rate limiting correctly
```

**Audit Required**:
```bash
# Find all references to lru_order and ip_requests
rg "lru_order|ip_requests" src/waf/ratelimit
```

**Effort**: Low
**Risk**: Low (removing dead code)
**Status**: Pending

---

### 4.2 Double URL Decoding - Document Limit

**Issue**: With `max_decode_passes=10`, deeply encoded payloads (11+ layers) may bypass detection. This is documented in normalizer.

#### Implementation Requirements

**Documentation** (add to `src/waf/attack_detection/normalizer.rs` comments):

```rust
/// Maximum URL decoding passes for SSRF/WAF detection.
/// Security Note: Payloads encoded with 11+ layers may bypass detection.
/// For high-security environments, consider increasing to 15-20 passes
/// or implementing rejection of extremely encoded requests.
const DEFAULT_MAX_DECODE_PASSES: usize = 10;
```

**Optional Enhancement**:
```rust
// If backend processes deeply encoded requests, increase default
const DEFAULT_MAX_DECODE_PASSES: usize = 20;  // From 10
```

**Effort**: Low
**Risk**: None
**Status**: Pending

---

### 4.3 Per-Site Upstream Connection Isolation

**Issue**: All sites share the same upstream connection pool. One high-traffic site can exhaust connections for others.

#### Implementation Requirements

**Current State**: All sites use a shared `UpstreamPool` with `max_connections=100` per backend.

**Desired State**: Each site has its own connection pool with configurable limits.

**File**: `src/proxy/mod.rs`

```rust
// Change from shared pool to per-site pools
pub struct ProxyServer {
    // Before: single pool
    // pool: UpstreamPool

    // After: per-site pools
    site_pools: RwLock<HashMap<String, UpstreamPool>>,
}
```

**Configuration**:
```toml
# In site proxy config
[site.mysite.proxy.upstream]
url = "http://backend:8000"
max_connections = 5000

[site.other_site.proxy.upstream]
url = "http://other:8000"
max_connections = 500
```

**Effort**: Medium
**Risk**: Low
**Status**: Enhancement (lower priority)

---

## Phase 5: Security Validation (No Action Required)

### 5.1 CRLF Injection - Well Protected ✅

**Finding**: `HeaderValidator::validate()` checks ALL headers for CRLF. `RequestSmugglingDetector` handles CL/TE conflicts. Coverage is solid.

**Evidence**:
- `HeaderValidator` (`header_validation.rs:63-77`) validates all headers
- `RequestSmugglingDetector::check_headers()` provides targeted checks
- HTTP/2 smuggling handled in `check_http2_smuggling()`

**No action required.**

---

## Implementation Order

| Priority | Item | Effort | Risk | Dependencies |
|----------|------|--------|------|--------------|
| 1 | IPv4-mapped IPv6 SSRF Fix | Low | Low | None |
| 2 | TLS Passthrough Warning Fix | Medium | Low | None |
| 3 | Threat Lookup Cache | Medium | Low | None |
| 4 | Connection Pool Config | Medium | Low | None |
| 5 | JWT Algorithm Confusion Fix | Medium | Low | None |
| 6 | DNS Rebinding SSRF Fix | High | Medium | Requires mesh DNS |
| 7 | Per-IP Blackhole Tracking | High | Medium | None |
| 8 | GeoIP Cache Size Increase | Low | None | None |
| 9 | LRU Eviction Dead Code Removal | Low | Low | None |
| 10 | URL Decode Limit Documentation | Low | None | None |
| 11 | Per-Site Connection Isolation | Medium | Low | None (enhancement) |
| - | CRLF Injection Protection | - | - | Already protected ✅ | |

---

## Configuration Summary

### Required Config Changes

```toml
# TLS Passthrough (security hardening)
[site.*.proxy]
# Default is now false (opt-in)
tls_passthrough = false  # Must be explicitly enabled

# WAF enforcement for passthrough
tls_passthrough_enforce_waf = true  # Required when tls_passthrough = true

# Connection Pool (scalability)
[site.high_traffic.proxy.upstream]
max_connections = 10000
pool_max_idle_per_host = 1000
pool_idle_timeout_secs = 120

# DNS Resolution for SSRF (security)
[waf.ssrf]
dns_resolution_enabled = true
dns_resolution_strategy = "mesh"  # or "third_party"
fallback_dns_servers = ["1.1.1.1:53", "8.8.8.8:53"]
dns_cache_ttl_secs = 60
allowlist_only_mode = true  # Performance

# Threat Lookup Cache (performance)
[mesh.threat_intel]
threat_lookup_cache_size = 10000
threat_lookup_cache_ttl_secs = 60

# GeoIP Cache (performance)
[waf.asn_tracking]
cache_size = 100000

# JWT Security (security)
[waf.jwt]
expected_algorithm = "RS256"
```

---

## Testing Requirements

### Unit Tests Required

| Item | Test Cases |
|------|-------------|
| IPv4-mapped IPv6 SSRF | `::ffff:192.168.1.1`, `::ffff:10.0.0.1`, `::ffff:127.0.0.1` |
| TLS Passthrough Warning | Verify ERROR log when passthrough without enforce_waf |
| JWT Algorithm Confusion | RS256→HS256 switch, HS256→RS256 switch |
| DNS Rebinding | `attacker.com` → public IP → private IP |
| Threat Lookup Cache | Cache hit, cache miss, TTL expiry |
| Connection Pool Config | Verify config applied to pool |
| Per-Site Connection Isolation | One site exhausts pool, other sites unaffected |

### Integration Tests Required

| Item | Test Cases |
|------|-------------|
| TLS Passthrough + WAF | Request with SQL injection through passthrough |
| DNS Resolution | Verify mesh DNS used vs third-party fallback |
| Blackhole Recovery | Per-IP recovery vs global recovery |
| CRLF Injection | Verify detection still works (regression) |

---

## Risk Summary

| Item | Risk Eliminated | Remaining Risk | Mitigation |
|------|-----------------|----------------|------------|
| TLS Passthrough | WAF bypass via passthrough | None | Opt-in + enforce_waf |
| JWT Algorithm Confusion | Algorithm confusion attack | Low | Pattern-based detection |
| IPv4-mapped IPv6 SSRF | SSRF bypass via IPv6 | None | Direct fix |
| DNS Rebinding | DNS rebinding attack | Medium | Mesh DNS or third-party |
| DHT Threat Lookup | Per-request latency | None | Caching |
| Connection Pools | Resource exhaustion | None | Configurable limits |
| Blackhole Mode | False positive collateral | Medium | Per-IP tracking |
| LRU Eviction | Dead code confusion | None | Removal |

---

## References

- Auth0 Research: "Critical vulnerabilities in JSON Web Token libraries" (2015)
- OWASP: HTTP Request Smuggling
- PortSwigger: SSRF URI parsing bypass techniques
- RFC 4034: RRSIG Timestamp Encoding (for DNSSEC)
- Cloudflare: Rate Limiting Best Practices

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/waf/attack_detection/ssrf.rs` | IPv4-mapped IPv6 detection, DNS resolver integration |
| `src/waf/attack_detection/jwt.rs` | Algorithm confusion detection |
| `src/waf/attack_detection/header_validation.rs` | No changes (already protected) |
| `src/tls/server.rs` | Wire proxy_raw_tcp, enforce rate limiting |
| `src/worker/unified_server.rs` | ERROR-level warnings, DNS resolver init |
| `src/config/site/proxy.rs` | Connection pool config fields |
| `src/proxy/mod.rs` | Apply connection pool config, per-site pools |
| `src/http_client/mod.rs` | Configurable pool settings |
| `src/mesh/threat_intel.rs` | Threat indicator caching |
| `src/waf/ratelimit/core.rs` | Per-IP blackhole tracking |
| `src/waf/ratelimit.rs` | Remove LRU dead code |
| `src/waf/asn_tracker.rs` | Configurable cache size |
| `src/config/defaults.rs` | Increase ASN cache default |

---

*Plan created based on comprehensive codebase review. Subject to revision based on implementation feedback.*

(End of file)