# ASN-Based Distributed Scraper Detection

## Problem Statement

Heavy-handed AI scraper bots distribute across many IPs within the same ASN to
circumvent per-IP rate limiting. Each individual IP stays under the per-IP
threshold, but collectively they constitute a DOS-style attack on smaller
websites. The current WAF has per-IP rate limiting (6 time windows) and UA-based
bot detection, but no ASN-level correlation.

## Existing Infrastructure

| Component | File | Status | Reuse |
|-----------|------|--------|-------|
| `GeoIpManager::get_asn_info()` | `src/geoip/mod.rs:186` | Exists, unused in HTTP path | ASN lookup engine |
| `GeoIpLookup::lookup_asn()` | `src/geoip/lookup.rs:121` | Exists, returns `(u32, String)` | Low-level IP→ASN |
| `maxminddb` crate | `Cargo.toml:171` | v0.27 with `mmap` | No new deps needed |
| `dashmap` crate | `Cargo.toml:85` | v5, used extensively | Concurrent per-ASN state |
| `lru_time_cache` crate | `Cargo.toml:202` | v0.11, used extensively | IP→ASN cache |
| `parking_lot` crate | `Cargo.toml:84` | v0.12 | Fast RwLock for GeoIP |
| `BlockStore` | `src/block_store.rs` | Fully functional | Block IPs from violating ASNs |
| `ThreatIntelligenceManager` | `src/mesh/threat_intel.rs` | Gossip/fanout mesh | Distribute ASN blocks |
| `ThreatType` enum | `src/mesh/protocol.rs:1080` | 4 variants today | Add `AsnBlock` |
| `AtomicSlidingWindow` | `src/waf/ratelimit/core.rs:124` | Lock-free, atomic | Per-ASN request counting |
| `ViolationTracker` | `src/waf/violation_tracker.rs` | Escalating bans | Escalating ASN bans |
| `NetworkPolicy` | `src/mesh/dht/network_policy.rs:5` | Distributed policy | ASN whitelist from global nodes |
| `ipnetwork` crate | `Cargo.toml:89` | v0.18 | CIDR representation (future) |

## Architecture

```
Request arrives → client_ip extracted from TCP socket
    │
    ▼
record_request()                         (existing, threat level)
    │
    ▼
ASN Tracker check                        (NEW)
    │  ┌─ GeoIpManager resolves IP → ASN (cached in LRU)
    │  ├─ If ASN in whitelist → skip, continue to rate limit
    │  ├─ Increment per-ASN AtomicSlidingWindow counters
    │  │   ├─ per_minute (60 buckets, 1s each)
    │  │   ├─ per_5min (60 buckets, 5s each)
    │  │   └─ per_hour (60 buckets, 60s each)
    │  ├─ Track unique IPs per ASN (DashMap, periodic cleanup)
    │  ├─ Check VOLUME threshold: ASN total requests > limit
    │  ├─ Check DISTRIBUTION threshold: unique IPs from ASN > limit
    │  ├─ If either exceeded → violation:
    │  │   ├─ record_attack_type("AsnScraping")  (metrics)
    │  │   ├─ record to ThreatLevelManager
    │  │   ├─ Block requesting IP via BlockStore
    │  │   ├─ announce_asn_block() to mesh
    │  │   └─ If violations >= threshold → escalate ban duration
    │  └─ Pass (ASN under thresholds)
    │
    ▼
check_rate_limit(client_ip, path)        (existing, per-IP)
    │
    ▼
check_ip_feed(client_ip)                 (existing)
    │
    ▼
... (rest of pipeline unchanged)
```

### Why Two Thresholds?

Volume alone is insufficient. A single compromised server in an ASN can generate
massive request volume (caught by existing per-IP rate limiting). The
**distribution threshold** catches the real threat: dozens of IPs each making
modest requests that individually pass per-IP limits but collectively represent
a distributed scraping campaign.

Example: 50 IPs from AS12345 each making 5 requests/minute = 250 req/min total.
Each IP is well under the default per-minute limit of 60, but the ASN-level
detection sees 50 unique IPs from one ASN within the window.

## New Module: `src/waf/asn_tracker.rs`

### Core Structs

```rust
pub struct AsnTracker {
    /// Per-ASN sliding window counters
    asn_windows: DashMap<u32, AsnWindowState>,

    /// IP → ASN cache (avoids repeated GeoIP lookups)
    asn_cache: parking_lot::RwLock<lru_time_cache::LruCache<IpAddr, u32>>,

    /// Configuration
    config: AsnScrapingConfig,

    /// GeoIP for ASN resolution
    geoip: Option<Arc<GeoIpManager>>,

    /// Block IPs from violating ASNs
    block_store: Option<Arc<BlockStore>>,

    /// Broadcast ASN blocks to mesh
    threat_intel: Option<Arc<ThreatIntelligenceManager>>,

    /// Escalating bans
    violation_tracker: Option<Arc<ViolationTracker>>,

    /// ASN whitelist (overridable by global nodes in mesh mode)
    whitelisted_asns: Arc<RwLock<HashSet<u32>>>,
}

pub struct AsnWindowState {
    /// Per-minute sliding window (60 buckets × 1s)
    per_minute: AtomicSlidingWindow,
    /// Per-5-minute sliding window (60 buckets × 5s)
    per_5min: AtomicSlidingWindow,
    /// Per-hour sliding window (60 buckets × 60s)
    per_hour: AtomicSlidingWindow,

    /// Unique IPs seen in current window (for distribution detection)
    /// Key: truncated IP (first 3 octets of v4, first /48 of v6)
    /// Value: first-seen timestamp
    unique_ips: DashMap<u32, u64>,

    /// Unique IP count at last cleanup
    unique_ip_count: AtomicU32,

    /// Violation tracking
    violation_count: u32,
    last_violation: Option<u64>,

    /// ASN metadata (for logging/metrics)
    organization: String,
}

pub enum AsnCheckResult {
    /// Request is allowed
    Pass,
    /// ASN violation detected, IP blocked
    Blocked { asn: u32, reason: String },
}
```

The `check_request()` method returns `Option<WafDecision>` (matching the
`check_rate_limit()`, `check_ip_feed()`, etc. pattern used throughout WafCore):
`None` = pass, `Some(WafDecision::Block(...))` = block. The `AsnCheckResult`
enum is used internally for logging/metrics before converting to `WafDecision`.

### Key Design Decisions

**1. `AtomicSlidingWindow` reuse** (from `src/waf/ratelimit/core.rs:124`)

The existing `AtomicSlidingWindow` is lock-free and atomic. It takes
`window_duration_secs` and `bucket_count` in its constructor. We reuse it
unchanged:

```rust
per_minute: AtomicSlidingWindow::new(60, 60),     // 60s window, 60 buckets
per_5min: AtomicSlidingWindow::new(300, 60),       // 300s window, 60 buckets
per_hour: AtomicSlidingWindow::new(3600, 60),      // 3600s window, 60 buckets
```

The `increment(now_ms)` method returns the current count after incrementing.
The `get_count(now_ms)` method returns the count without incrementing.

**2. IP→ASN cache with `lru_time_cache`**

The GeoIP lookup acquires a read lock on `GeoIpLookup` inside `GeoIpManager`
(`parking_lot::RwLock`). This is fast (memory-mapped MMDB read), but we cache
results to avoid the lock acquisition on every request:

```rust
asn_cache: parking_lot::RwLock::new(
    lru_time_cache::LruCache::with_capacity(config.cache_size) // default 10000
),
```

Cache lookup is O(1) with `parking_lot::RwLock` read lock (no poisoning risk,
faster than `std::sync::RwLock`). Cache miss path: acquire GeoIP read lock →
`lookup_asn()` → insert into cache.

**3. Unique IP tracking uses truncated IPs**

Full `IpAddr` as a DashMap key is expensive (16 bytes for v6). Instead, truncate
to a `u32`:

- IPv4: first 3 octets (e.g., `203.0.113.x` → `0xCB007100`, /24 granularity)
- IPv6: first 24 bits of the interface identifier

This gives per-/24 granularity, which is sufficient for detecting distributed
botnets. A single ASN hosting multiple /24 blocks of scrapers will be detected.

**4. DashMap for concurrent access**

`DashMap` is used extensively in the codebase (118 occurrences). It provides
sharded concurrent HashMap access without explicit locking. Used for:
- `asn_windows: DashMap<u32, AsnWindowState>` — keyed by ASN number
- `unique_ips: DashMap<u32, u64>` — per-ASN unique IP tracking

**5. No new dependencies**

All required crates are already in `Cargo.toml`:
- `dashmap = "5"`
- `lru_time_cache = "0.11"`
- `parking_lot = "0.12"`
- `maxminddb = "0.27"` (with `mmap`)

## Configuration

### Global Config (`src/config/defaults.rs`)

New section added to `DefaultsConfig`:

```rust
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AsnScrapingConfig {
    #[serde(default = "default_asn_scraping_enabled")]
    pub enabled: bool,                          // default: false (opt-in)

    #[serde(default = "default_asn_requests_per_minute")]
    pub requests_per_minute: u32,               // default: 300

    #[serde(default = "default_asn_requests_per_5min")]
    pub requests_per_5min: u32,                 // default: 1000

    #[serde(default = "default_asn_requests_per_hour")]
    pub requests_per_hour: u32,                 // default: 5000

    #[serde(default = "default_asn_unique_ips_threshold")]
    pub unique_ips_threshold: u32,              // default: 50

    #[serde(default = "default_asn_unique_ips_window_secs")]
    pub unique_ips_window_secs: u64,            // default: 300

    #[serde(default = "default_asn_violations_before_block")]
    pub violations_before_block: u32,           // default: 2

    #[serde(default = "default_asn_ban_duration_secs")]
    pub ban_duration_secs: u64,                 // default: 3600

    #[serde(default = "default_asn_cache_size")]
    pub cache_size: usize,                      // default: 10000

    #[serde(default)]
    pub whitelisted_asns: Vec<u32>,             // default: see below
}
```

### Default Whitelisted ASNs

These are never blocked by ASN scraping detection (search engines, CDNs,
major cloud providers that host legitimate services):

| ASN | Organization | Rationale |
|-----|-------------|-----------|
| 15169 | Google | Search crawler, Googlebot |
| 13335 | Cloudflare | CDN, reverse proxy |
| 8075 | Microsoft | Bing, Azure |
| 32934 | Meta/Facebook | Link preview crawlers |
| 14906 | Apple | Applebot |
| 20940 | Akamai | CDN |
| 16625 | Akamai | CDN |
| 13414 | Twitter/X | Link preview |
| 14618 | Amazon | AWS (mixed use, but too large to block) |
| 16509 | Amazon | AWS |
| 3836 | Verizon | Major ISP |
| 7922 | Comcast | Major ISP |

### TOML Config Example

```toml
[defaults.asn_scraping]
enabled = true
requests_per_minute = 300
unique_ips_threshold = 50
unique_ips_window_secs = 300
violations_before_block = 2
ban_duration_secs = 3600
whitelisted_asns = [15169, 13335, 8075, 32934]
```

### Per-Site Config (`src/config/site.rs`)

```rust
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteAsnScrapingConfig {
    #[serde(default)]
    pub enabled: Option<bool>,

    #[serde(default)]
    pub requests_per_minute: Option<u32>,

    #[serde(default)]
    pub unique_ips_threshold: Option<u32>,

    #[serde(default)]
    pub whitelisted_asns: Vec<u32>,
}
```

Per-site overrides are merged with global defaults at site load time.

## File-by-File Changes

### 1. `src/waf/asn_tracker.rs` (NEW, ~350 lines)

The core detection engine. Contains:

- `AsnTracker` struct and `AsnScrapingConfig` (re-exported from config)
- `AsnWindowState` per-ASN sliding window state
- `AsnCheckResult` enum (Pass / Blocked)
- `check_request()` method: the hot-path check
- `block_asn_violation()` method: handles violation + blocking
- `update_whitelist()` method: for global node overrides
- `cleanup_unique_ips()` background task: periodic rotation of unique IP sets
- Unit tests

### 2. `src/waf/mod.rs` (~40 lines changed)

- Add `pub mod asn_tracker;` declaration (top of file)
- Add `pub use asn_tracker::{AsnTracker, AsnCheckResult};` to re-exports (line ~29)
  — note: `AsnScrapingConfig` lives in `src/config/defaults.rs` and is referenced
  as `crate::config::AsnScrapingConfig`, not re-exported from waf module
- Add `pub asn_tracker: Option<Arc<AsnTracker>>` field to `WafCore` struct (after line 148)
- Add `geoip_config: Option<crate::config::geoip::GeoIpConfig>` field to `WafCoreConfig` (line ~263)
- Add `asn_scraping_config: Option<crate::config::AsnScrapingConfig>` to `WafCoreConfig`
- In `WafCore::new()`: if `asn_scraping_config` is `Some` and enabled, create
  `GeoIpManager::new(geoip_config, &[])` — if it returns `Some`, construct
  `AsnTracker` with it. If GeoIP creation fails, ASN tracking silently disables.
- Insert `check_asn_scraping()` call in `check_request_full()` between `record_request()` (line 669) and `check_rate_limit()` (line 673)
- New `check_asn_scraping(&self, client_ip: IpAddr) -> Option<WafDecision>` method on `WafCore` — accesses `self.threat_level` internally for ban duration, passes `client_ip` to `self.asn_tracker`
- Add `asn_off: bool` to `TestModeConfig` (line ~155), default false

### 3. `src/config/defaults.rs` (~70 lines)

- Add `AsnScrapingConfig` struct with serde defaults and `Default` impl
- Add `pub asn_scraping: AsnScrapingConfig` field to `DefaultsConfig` (line ~46)
- Add default functions for each field
- Update `DefaultsConfig::default()` implementation

### 4. `src/config/site.rs` (~30 lines)

- Add `SiteAsnScrapingConfig` struct (after `SiteGeoipConfig` around line 1599)
- Add `pub asn_scraping: SiteAsnScrapingConfig` to `SiteConfig` (after line 68)
- Default all fields to `None` / empty

### 5. `src/mesh/protocol.rs` (~3 lines)

- Add `AsnBlock` variant to `ThreatType` enum (line 1084, after `SuspiciousActivity`)

### 6. `src/mesh/protocol_types.rs` (~3 lines)

- Add `4 => ThreatType::AsnBlock` to the decode match (line 535)
- Encode side needs no change (uses `as i32` enum discriminant, `AsnBlock` = 4)

### 7. `src/mesh/threat_intel.rs` (~80 lines)

- New `announce_asn_block()` method (follows `announce_local_block()` pattern at line 231)
  - `indicator_value` = ASN number as string (e.g., `"16509"`)
  - `threat_type` = `ThreatType::AsnBlock`
  - `severity` = `ThreatSeverity::High`
  - `reason` = format with ASN + violation details
- Handle `ThreatType::AsnBlock` in `handle_incoming_threat()` match (line 522)
  - Parse ASN from `indicator_value`
  - Call new `apply_asn_block_mesh_action()` helper
- New `apply_asn_block_mesh_action()` method
  - Block all known IPs from that ASN in the local BlockStore
  - Log the mesh-originated ASN block

### 8. `src/config/main.rs` (~5 lines)

- Add `pub geoip: GeoIpConfig` field to `MainConfig` struct (with `#[serde(default)]`)
- Import `GeoIpConfig` (already at `src/config/geoip.rs`)
- Default: `GeoIpConfig::default()` — disabled, no database path

### 9. `src/server/mod.rs` (~10 lines)

- In `create_waf()` (line 382), add `geoip_config` and `asn_scraping_config` fields to `WafCoreConfig`
- `geoip_config: Some(main_config.geoip.clone())`
- `asn_scraping_config: Some(main_config.defaults.asn_scraping.clone())` (if enabled)
- GeoIpManager creation happens inside `WafCore::new()`, not here

### 10. `src/worker/connection.rs` (~5 lines)

- In `create_waf()` (line 25), add same `geoip_config` and `asn_scraping_config` fields

### 11. `src/mesh/dht/network_policy.rs` (~20 lines)

- Add `pub whitelisted_asns: Vec<u32>` field to `NetworkPolicy` (line 13)
- Update `NetworkPolicy::new()` to accept and default the field
- Update `get_signable_content()` to include ASN whitelist (line 39)
- Global nodes distribute ASN whitelist via existing `NetworkPolicyUpdate` message

### 12. `src/mesh/dht/record_store.rs` (~15 lines)

- When `NetworkPolicy` is received with `whitelisted_asns`, propagate to `AsnTracker`
- Add handler that calls `asn_tracker.update_whitelist()`

### 13. `src/metrics/mod.rs` (~10 lines)

- Use existing `record_attack_type("AsnScraping")` pattern — no new metric structs needed
- The `get_attack_type_counts()` function will automatically surface "AsnScraping" counts

## Request Pipeline Integration

The ASN check is inserted early in `check_request_full()` (`src/waf/mod.rs:659`):

```rust
pub async fn check_request_full(
    &self,
    client_ip: std::net::IpAddr,
    method: &str,
    path: &str,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body: Option<&[u8]>,
    user_agent: Option<&str>,
) -> WafDecision {
    // Record for threat level baseline
    if let Some(ref tl) = self.threat_level {
        tl.record_request();
    }

    // NEW: ASN scraping detection (before per-IP rate limit)
    if !self.test_mode.enabled || !self.test_mode.asn_off {
        if let Some(ref tracker) = self.asn_tracker {
            if let Some(decision) = tracker.check_request(client_ip) {
                return decision;
            }
        }
    }

    // Existing per-IP rate limit
    if let Some(decision) = self.check_rate_limit(client_ip, path).await {
        return decision;
    }

    // ... rest unchanged
}
```

### Why Insert Before Rate Limiting?

The ASN check must run before per-IP rate limiting because:
1. If the ASN is already known-bad, we want to block immediately without
   doing the more expensive per-IP rate limit computation
2. The ASN check is cheap (cache lookup + atomic increment)
3. Rate limit violations would trigger `ViolationTracker` recording that
   would be redundant if we're about to block for ASN reasons

## Mesh Integration

### New `ThreatType::AsnBlock`

```rust
// src/mesh/protocol.rs:1080
pub enum ThreatType {
    Unspecified,         // 0
    IpBlock,             // 1
    RateLimitViolation,  // 2
    SuspiciousActivity,  // 3
    AsnBlock,            // 4  ← NEW
}
```

### Threat Indicator Format

```rust
ThreatIndicator {
    threat_type: ThreatType::AsnBlock,
    indicator_value: "16509".to_string(),          // ASN number as string
    severity: ThreatSeverity::High,
    reason: "asn_scraping:volume:305r/m".to_string(), // reason with details
    ttl_seconds: 3600,                              // ban duration
    source_node_id: self.node_id.clone(),
    timestamp: now,
    site_scope: "global".to_string(),
    rate_limit_requests: Some(305),                 // actual request count
    rate_limit_window_secs: Some(60),               // window
    suspicious_pattern: None,
    signature: Vec::new(),
    signer_public_key: None,
}
```

### Receiving Node Behavior

When a node receives `ThreatType::AsnBlock`:
1. Parse ASN from `indicator_value`
2. Add ASN to local `AsnTracker`'s blocked/violation state
3. Log: `"Applied mesh ASN block from {node}: AS{asn} (reason, TTL)"`
4. Next request from that ASN triggers immediate block

### Global Node ASN Whitelist

Global nodes can override the per-node ASN whitelist via the existing
`NetworkPolicyUpdate` mechanism:

```rust
// src/mesh/dht/network_policy.rs
pub struct NetworkPolicy {
    pub min_reputation_for_read: i64,
    pub min_reputation_for_write: i64,
    pub blocked_nodes: Vec<BlockedNode>,
    pub whitelisted_asns: Vec<u32>,  // ← NEW
    pub last_updated: u64,
    pub updated_by: String,
    pub valid_from: u64,
    pub signature: Vec<u8>,
}
```

When an edge node receives a `NetworkPolicyUpdate` with `whitelisted_asns`,
it replaces its local ASN whitelist with the global node's list. This gives
global nodes authoritative control over which ASNs are protected across the
entire mesh.

## Detection Logic Detail

### Volume Check

```
for each time window (minute, 5min, hour):
    count = window.increment(now_ms)
    if count > threshold:
        violation = true
```

### Distribution Check

```
unique_ip_key = truncate_ip(client_ip)  // /24 for v4
asn_state.unique_ips.insert(unique_ip_key, now)
unique_count = asn_state.unique_ips.len()

// Periodic cleanup removes entries older than unique_ips_window_secs
if unique_count > unique_ips_threshold:
    violation = true
```

### Violation Escalation

Mirrors the existing `ViolationTracker` pattern:

| Violation # | Ban Duration |
|-------------|-------------|
| 1 | `ban_duration_secs` (default: 1 hour) |
| 2 | `ban_duration_secs * 2` (2 hours) |
| 3 | `ban_duration_secs * 4` (4 hours) |
| N | `ban_duration_secs * 2^(N-1)` |

If threat level is elevated, the base ban duration follows the existing
escalation table (1h/4h/24h/7d/permanent by level).

## Testing Strategy

### Unit Tests (in `src/waf/asn_tracker.rs`)

- **Threshold detection**: Create tracker with low threshold, push requests
  from same ASN, verify block after threshold
- **Distribution detection**: Many unique IPs from same ASN, each under
  volume limit, verify block
- **Whitelist bypass**: Whitelisted ASN never triggers block
- **Cache behavior**: Verify LRU eviction, cache hit/miss paths
- **Window sliding**: Verify counters expire correctly after window passes

### Mock GeoIP (for tests without real MMDB)

```rust
#[cfg(test)]
fn mock_geoip() -> GeoIpManager {
    // Use GeoIpLookup::load_database_from_slice() with a minimal test MMDB
    // Or: create a test wrapper that returns hardcoded ASN mappings
}
```

### Integration Tests (in `tests/integration_test.rs`)

- **Mesh ASN block propagation**: Create `ThreatIndicator` with `AsnBlock`,
  verify round-trip through proto encode/decode (ThreatType discriminant = 4)
- **Global node whitelist override**: Verify `NetworkPolicy` with
  `whitelisted_asns` propagates to edge nodes

### Proto Encode/Decode Verification

The `ThreatType` enum uses `as i32` for encoding (line `protocol_types.rs:511`),
so `AsnBlock` (variant 4) encodes as integer `4`. The decode side
(`protocol_types.rs:531-535`) needs `4 => ThreatType::AsnBlock`. Test with:

```rust
#[test]
fn test_asn_block_threat_type_roundtrip() {
    let indicator = ThreatIndicator {
        threat_type: ThreatType::AsnBlock,
        indicator_value: "16509".to_string(),
        // ... minimal fields
    };
    let pb: proto::ThreatIndicator = indicator.clone().into();
    assert_eq!(pb.threat_type, 4);
    let decoded: ThreatIndicator = pb.into();
    assert_eq!(decoded.threat_type, ThreatType::AsnBlock);
}
```

## Implementation Order

1. **Config** — `src/config/defaults.rs` + `src/config/site.rs` + `src/config/main.rs` (add `geoip` field)
2. **Core tracker** — `src/waf/asn_tracker.rs`
3. **WAF integration** — `src/waf/mod.rs` (struct fields, pipeline insertion)
4. **Server wiring** — `src/server/mod.rs` + `src/worker/connection.rs`
5. **Mesh protocol** — `src/mesh/protocol.rs` + `src/mesh/protocol_types.rs`
6. **Mesh threat intel** — `src/mesh/threat_intel.rs`
7. **Global node whitelist** — `src/mesh/dht/network_policy.rs` + `record_store.rs`
8. **Tests** — unit + integration

---

## Future Work

### 1. Per-Site ASN Thresholds

The `SiteAsnScrapingConfig` struct supports per-site overrides in the config
schema, but the initial implementation uses global defaults. Full per-site
support requires:

- Resolving per-site config at request time (the `SiteConfig` is available in
  `ProxyServer` but not directly in `WafCore`)
- Per-site `AsnTracker` instances or a nested `DashMap<String, DashMap<u32, ...>>`
- Per-site ASN reputation state

**Complexity**: Medium. The config plumbing exists but the runtime lookup needs
site context from the proxy layer.

### 2. ASN Reputation Scoring

Instead of binary pass/block, track a continuous reputation score per ASN that
modifies WAF behavior proportionally. Three candidate algorithms:

**Exponential Decay** (recommended starting point):
```
score(t) = score(t-1) * e^(-λ * Δt) + current_window_weight
```
Half-life of 7 days. Simple, O(1) per update. Reputation slowly recovers after
a DDoS campaign ends.

**Bayesian Beta-Binomial**:
```
Prior: Beta(α₀, β₀) where α₀ = 1 (attacks), β₀ = 100 (legitimate)
Update: α += attacks_in_window, β += legitimate_requests_in_window
Reputation = α / (α + β)
```
Naturally handles the "innocent ASN" problem via a strong prior — a large ASN
with 0.1% attack rate stays near baseline.

**Z-Score Relative** (integrates with existing `ThreatLevel` scorer):
Compute per-ASN attack rate, compare against baseline using the existing
`BaselineStats` / `RunningStatistics` from `src/waf/threat_level/baseline.rs`.

**Behavioral impact at different reputation levels**:

| Reputation | Rate Limit | Violations to Block | Challenge |
|-----------|-----------|-------------------|-----------|
| 0.0–0.2 (clean) | Normal | 3 | Normal |
| 0.2–0.5 (suspicious) | 75% | 2 | More aggressive |
| 0.5–0.8 (malicious) | 50% | 1 | Always challenge |
| 0.8–1.0 (hostile) | 25% | Immediate | Hard block |

**Innocent ASN protection**: Track ratio of offending IPs to total unique IPs
seen. If < 1% of IPs are offending, likely an isolated compromise, not
systematic abuse. Apply partial or no penalty.

**Complexity**: High. Requires new `src/waf/asn_reputation/` module (~500 lines),
integration with `ThreatScorer`, and JSON persistence.

### 3. IP Range Blocking (ASN-to-CIDR Prefix Resolution)

When blocking an ASN, blocking individual IPs as they arrive is slow to ramp up.
Blocking the ASN's CIDR prefixes provides immediate coverage.

**Data sources for ASN→prefix mapping**:

| Source | Format | Coverage | Notes |
|--------|--------|----------|-------|
| RIPE RIS API | JSON per-ASN query | ~95% global routing | Free, `stat.ripe.net/data/prefix-asn-set/` |
| BGPView API | JSON per-ASN query | Comprehensive | Free, `api.bgpview.io/asn/{asn}/prefixes` |
| CAIDA RouteViews | Full BGP table, text | Most complete | ~50-80MB, updated every 8h |
| MaxMind GeoIP | IP→ASN only | Per-lookup | Already in use, cannot enumerate prefixes |

**MaxMind does NOT provide prefix enumeration** — it only does forward lookups
(IP → ASN). A separate data source is needed for ASN → prefixes.

**Recommended approach**: Lazy loading with background refresh.
1. When ASN is first blocked, query RIPE RIS API for its prefixes
2. Cache the prefix list in memory
3. Background task re-queries every 24h
4. While loading, fall back to GeoIP per-request lookup (existing path)

**Storage**: The `iptrie` crate (BDD-based trie, v0.11.1) provides O(1)
amortized `contains()` for prefix sets. Alternatively, sorted `Vec<IpNetwork>`
with binary search gives O(log n). For 10K prefixes: ~14 comparisons = ~70ns.

**Performance difference**:
- Current linear scan (`src/waf/ip_feed.rs:194`): O(n), ~50µs at 10K networks
- Trie lookup: O(1) amortized, ~100ns
- **~500x improvement** for large prefix sets

**False positive mitigation**: Critical for cloud provider ASNs.
- Exemption CIDRs (block ASN but allow specific subnets)
- Per-site scope (site A blocks AWS, site B allows it)
- Warning when blocking ASNs with > 500 prefixes

**Complexity**: Medium-high. New `src/waf/asn_block.rs` module, RIPE RIS HTTP
client, `iptrie` dependency (optional).

### 4. JA3/JA4 TLS Fingerprinting

TLS fingerprinting detects bots that spoof user-agents but cannot easily change
their TLS handshake characteristics. Python `requests`, Go `http`, Node.js
`fetch`, and headless Chrome all have distinctive TLS fingerprints.

**Current TLS stack**: `rustls 0.23.37` with `tokio-rustls 0.26.4`.

**JA3 feasibility with rustls**: **NOT FEASIBLE** with current API.
- JA3 requires extension ordering as sent on the wire — not exposed by rustls
- EC point formats — not exposed
- Full extension type list — not exposed

**JA4 feasibility with rustls**: **PARTIALLY FEASIBLE**.
- Cipher suites, named groups, signature schemes, ALPN are available via
  `rustls::server::ClientHello`
- Full extension list is NOT available
- TLS version from record layer is NOT directly available

**Recommended approach**: Pre-rustls raw TLS parsing.

Intercept the raw TCP stream before it reaches `TlsAcceptor`, peek at the first
TLS record to extract ClientHello bytes, parse with `tls-parser` crate, compute
JA3/JA4, then pass the unconsumed stream to rustls normally.

```
TCP stream → peek bytes → parse ClientHello (tls-parser)
    → compute JA3/JA4 hash
    → pass to TlsAcceptor.accept()
```

The `tls-parser` crate (v0.12.2, nom-based, actively maintained) can extract:
- TLS version from record header
- Cipher suite list (as u16 values)
- Extension list with types and ordering
- Named groups, EC point formats, signature algorithms, ALPN

**Bot detection value**: High. Known fingerprint databases (ja4db.com) map
fingerprints to applications:
- Chrome: `JA4=t13d1516h2_8daaf6152771_02713d6af862`
- Python requests: Distinctive (no ALPN h2, different ciphers)
- Go http client: Distinctive cipher ordering
- Scraping frameworks (Playwright, Puppeteer): Detectable differences from
  real browsers

**Integration with ASN detection**: TLS fingerprints can confirm ASN-level
suspicion. If 50 IPs from AS12345 all present a Python requests fingerprint,
that's strong evidence of a coordinated scraping operation.

**Complexity**: Medium. New `src/tls/fingerprint.rs` module (~200 lines),
`tls-parser` dependency, modifications to `src/tls/server.rs` to peek before
accept. No rustls fork required.

**Alternative (future)**: Rustls PR #2502 (merged June 2025) introduced
`ClientExtensions` type. Future rustls versions (0.24+) may expose extension
type IDs directly, making JA4 computation trivial without raw byte parsing.

### 5. Cross-Feature Synergies

| Combination | Benefit |
|------------|---------|
| ASN detection + TLS fingerprinting | Confirm coordinated scraping: same ASN + same bot fingerprint |
| ASN reputation + per-site thresholds | Different tolerance per site (blog vs. API) |
| ASN detection + IP range blocking | Immediate ASN-wide blocking via CIDR prefixes |
| ASN reputation + threat level z-scores | Feed ASN health into global threat assessment |
| Mesh ASN blocks + global node whitelist | Network-wide ASN policy with centralized control |
