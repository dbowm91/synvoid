# WAF Module Architecture

## 1. Purpose and Responsibility

The Web Application Firewall (WAF) module (`src/waf/`) provides comprehensive request filtering, attack detection, and threat mitigation for the SynVoid proxy. It serves as the primary security layer that inspects incoming HTTP requests and determines whether to allow, block, or challenge traffic based on multiple detection mechanisms.

**Core Responsibilities:**
- Request filtering and threat detection across all HTTP inputs
- Bot detection and AI crawler blocking
- Rate limiting and traffic shaping
- Threat intelligence correlation and enforcement
- Honeypot-based attack capture
- Endpoint protection and sensitive path blocking
- Violation tracking and threat level management

## 2. Key Submodules and Their Responsibilities

### 2.1 `mod.rs` - WafCore (936 lines)

The central orchestrator that coordinates all WAF components.

**WafCore** - Main entry point for request processing:
- Manages the complete request checking pipeline
- Coordinates between rate limiting, bot detection, attack detection, and threat intelligence
- Handles decision escalation based on threat levels
- Manages honeypot interactions and tarpit responses

**Key Components:**
```rust
pub struct WafCore {
    pub rate_limiter: RateLimiterManager,           // Rate limiting engine
    pub bot_detector: BotDetector,                   // Bot detection
    pub endpoint_blocker: EndpointBlockerManager,     // Path blocking
    pub sensitive_endpoint_manager: SensitiveEndpointManager, // Honeypot endpoints
    pub error_page_manager: ErrorPageManager,
    pub challenge_manager: ChallengeManager,         // JS/PoW challenges
    pub attack_detector: ArcSwapOption<AttackDetector>, // Attack detection
    pub threat_level: Option<Arc<ThreatLevelManager>>, // Threat escalation
    pub violation_tracker: Option<Arc<ViolationTracker>>,
    pub ip_feed: Option<Arc<IpFeedManager>>,         // IP block feeds
    pub traffic_shaper: Option<Arc<GlobalTrafficShaper>>,
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    pub asn_tracker: Option<Arc<AsnTracker>>,
    pub flood_protector: Option<Arc<FloodProtector>>,
}
```

**Main Entry Point - `check_request_full()`:**
The primary method for processing requests through the WAF pipeline:
1. Check block store (pre-blocked IPs)
2. Check rate limits
3. Check endpoint blocking rules
4. Check honeypot paths
5. Check bot protection
6. Check flood protection
7. Run attack detection (parallel execution)

### 2.2 `attack_detection/` - Attack Detection Engine

Comprehensive attack detection with 13 specialized detectors.

**Key Files:**
- `mod.rs` (64-86 lines) - `AttackDetector` orchestrates all sub-detectors
- `config.rs` - `AttackDetectionConfig` with 13 detector configurations
- `normalizer.rs` - Input normalization with multi-pass decoding
- `streaming.rs` - `StreamingWafCore` for chunk-based body inspection
- Sub-detectors for each attack type

**Supported Attack Types:**
| Detector | File | Description |
|----------|------|-------------|
| SQL Injection | `sqli.rs` | SQLi detection via libinjection + patterns |
| XSS | `xss.rs` | Cross-site scripting detection |
| Path Traversal | `path_traversal.rs` | Directory traversal attacks |
| RFI | `rfi.rs` | Remote file inclusion |
| SSRF | `ssrf.rs` | Server-side request forgery (blocks private IPs) |
| SSTI | `ssti.rs` | Server-side template injection |
| Command Injection | `cmd_injection.rs` | OS command injection |
| XXE | `xxe.rs` | XML external entity attacks |
| JWT | `jwt.rs` | JWT validation and tampering |
| Request Smuggling | `request_smuggling.rs` | HTTP desync attacks |
| LDAP Injection | `ldap_injection.rs` | LDAP injection |
| XPath Injection | `xpath_injection.rs` | XPath injection |
| Open Redirect | `open_redirect.rs` | Open redirect exploitation |

**Architecture:**
- **Fast-path pre-screening**: RegexSet with 50+ patterns for quick rejection
- **Input normalization**: Multi-pass URL decoding, HTML entity decoding, Unicode normalization
- **Parallel detection**: Heavy detectors run concurrently via `JoinSet`
- **Anomaly scoring**: Optional cumulative scoring across detectors
- **Streaming support**: `StreamingWafCore` for chunk-based body inspection

**Behavioral Analysis:**
- Standalone `BehavioralEngine` extracts request features
- When `mesh` feature enabled: `BehavioralIntelligenceManager` for collaborative threat intel
- Features: URL entropy, timing variance, header analysis, body/header ratio

### 2.3 `bot.rs` - Bot Detection (494 lines)

Detects and manages bot traffic with multiple fingerprinting methods.

**BotDetector Structure:**
```rust
pub struct BotDetector {
    known_bots_allow: Arc<HashSet<String>>,      // Whitelisted bots
    ai_crawlers_block: Arc<HashSet<String>>,    // AI crawlers to block
    scraper_patterns: Arc<HashSet<String>>,     // Scraper patterns
    known_bot_ja3_hashes: Arc<HashSet<String>>, // TLS fingerprinting
    known_bot_ja4_hashes: Arc<HashSet<String>>, // TLS fingerprinting
    block_ai_crawlers: bool,
    block_scrapers: bool,
}
```

**Detection Methods:**
1. JA3/JA4 TLS fingerprint matching (highest priority)
2. Known bot UA allowlist (Googlebot, Bingbot, etc.)
3. `isbot` crate detection
4. AI crawler pattern matching
5. Scraper pattern matching (curl, wget, python-requests)

**Detection Results:**
```rust
pub enum BotDetectionResult {
    Allowed { reason: String },
    Blocked { reason: String, bot_type: String },
    Tarpit { reason: String, bot_type: String },
}
```

### 2.4 `ratelimit.rs` - Rate Limiting

Hierarchical rate limiting with site isolation.

**Components:**
- `RateLimiterManager` - Main entry point with site-sharded state
- `GlobalRateLimiter` - Global request rate limiting
- `SlottedIpRateLimiter` - Per-IP rate limiting with shared memory support
- `RingBuffer` - Efficient time-window tracking

**Key Features:**
- Site isolation: Same IP can have different limits per site
- Sharded state: Reduces lock contention with `DashMap`
- Blackhole mechanism: Gradual IP unblocking after sustained good behavior
- Shared memory: Optional mmap-based shared state for multi-process deployment

**RateLimitResult:**
```rust
pub enum RateLimitResult {
    Allowed,
    Limited { limit_type: String, retry_after_millis: u64 },
    Blackholed,
}
```

### 2.5 `traffic_shaper/` - Traffic Shaping and Connection Limiting

**GlobalTrafficShaper** (`global.rs`):
- Token bucket-based bandwidth limiting
- Ingress/egress rate limiting with burst allowance
- Monthly cap enforcement
- Threat level multiplier adjustment

```rust
pub struct GlobalTrafficShaper {
    config: GlobalTrafficShapingConfig,
    bandwidth_config: BandwidthConfig,
    ingress_bucket: Arc<AsyncTokenBucket>,
    egress_bucket: Arc<AsyncTokenBucket>,
}
```

**ConnectionLimiter** (`limiter.rs`):
- Global connection limits
- Per-IP connection limits
- Per-site connection limits
- Burst token system
- Connection queue with timeout

**SiteConnectionLimiter**: Per-site wrapper with site-specific limits.

**Error Types:**
```rust
pub enum ConnectionLimitError {
    GlobalLimitExceeded,
    PerIpLimitExceeded,
    BurstExceeded,
    SiteLimitExceeded,
    QueueFull,
    QueueTimeout,
    QueueClosed,
}
```

### 2.6 `threat_level/` - Threat Level Management

Manages threat escalation based on violation tracking:
- Tracks attack frequency and severity
- Implements escalation policies
- Provides throttling multipliers for traffic shaping
- Persists violation history for pattern analysis

### 2.7 `violation_tracker.rs` - Violation Tracking

Records and tracks security violations:
- Stores per-IP violation history
- Implements persistence with configurable intervals
- Triggers automatic blocking after threshold violations
- Supports normal and attack-mode persistence intervals

### 2.8 `ip_feed.rs` - IP Feed Management

Manages external IP block feeds:
- Background feed fetching
- Automatic feed refresh
- Integration with block store for immediate enforcement

### 2.9 `asn_tracker.rs` - ASN-based Tracking

Tracks and blocks traffic by Autonomous System Number:
- ASN-based rate limiting
- Scraping detection per ASN
- Integration with GeoIP for ASN resolution

### 2.10 `probe_tracker.rs` - Honeypot Probe Tracking

Tracks access to honeypot endpoints:
- Records endpoint access patterns
- Automatic IP blocking for honeypot hits
- Configurable thresholds and ban durations

### 2.11 `endpoints.rs` - Endpoint Protection

Manages endpoint blocking and sensitive path protection:
- `EndpointBlockerManager` - Blocks paths by regex or exact match
- `SensitiveEndpointManager` - Honeypot endpoint detection
- `ErrorPageManager` - Custom error page serving

### 2.12 `flood/` - Flood Protection

TCP flood protection (requires `flood-ebpf` feature on Linux):
- eBPF-based SYN flood detection
- Mitigation providers for different attack scenarios
- Connection tracking and rate limiting

### 2.13 `threat_intel/` - Threat Intelligence (Mesh-only)

Distributed threat intelligence via DHT:
- `ThreatFeedClient` - Subscribes to threat feeds
- `ThreatFeedIndicator` - Individual threat indicators
- Collaborative threat sharing across mesh nodes

### 2.14 `rule_feed.rs` - Rule Feed Management

Manages external rule feeds:
- YARA rule compilation and matching
- Rule feed fetching and updates
- Integration with attack detection

## 3. Major Data Structures and Types

### WafDecision - Request Disposition

```rust
pub enum WafDecision {
    Pass,                                    // Allow request
    Block(u16, String),                      // Block with status code and reason
    Drop,                                    // Silently drop connection
    Tarpit(String),                          // Tarpit with path-specific response
    Stall,                                   // Delay response
    Challenge(ChallengeType, String),        // Challenge without cookie
    ChallengeWithCookie {                    // Challenge with session cookie
        challenge_type: ChallengeType,
        html: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
}
```

### AttackDetectionResult

```rust
pub struct AttackDetectionResult {
    pub attack_type: AttackType,
    pub fingerprint: Option<String>,
    pub matched_pattern: Option<String>,
    pub input_location: InputLocation,
}

pub enum AttackType {
    Sqli, Xss, PathTraversal, Rfi, Ssrf, Ssti,
    CmdInjection, Xxe, Jwt, RequestSmuggling,
    LdapInjection, XPathInjection, OpenRedirect, Other,
}

pub enum InputLocation {
    QueryString, PostBody, Header(Arc<str>), Path, Cookie(Arc<str>),
}
```

### WafConfig and WafCoreConfig

```rust
pub struct WafConfig {
    pub enable_css_honeypot: bool,
    pub enable_pow_challenge: bool,
    pub enable_auth_challenge: bool,
    pub auth_login_path: String,
    pub block_ai_crawlers: bool,
    pub drop_blocked_requests: bool,
    pub test_mode: TestModeConfig,
    pub honeypot_ban_duration_secs: u64,
    pub css_exempt_paths: Vec<String>,
}

pub struct WafCoreConfig {
    pub rate_config: RateLimitConfigStore,
    pub memory_config: RateLimitMemoryConfig,
    pub bot_config: BotDefaults,
    pub waf_config: WafConfig,
    pub attack_detection_config: Option<AttackDetectionConfig>,
    pub threat_level_config: Option<ThreatLevelConfig>,
    pub traffic_shaping_config: Option<TrafficShapingConfig>,
    pub bandwidth_config: BandwidthConfig,
    // ... more fields
}
```

### StreamingWafCore - Chunk-based Body Inspection

```rust
pub struct StreamingWafCore {
    inner: Arc<AttackDetector>,
    chunk_size: usize,
    max_buffered_bytes: usize,
    state: StreamingState,
}

enum StreamingWafDecision {
    Continue,
    Block(u16, String),
}

enum MultipartState {
    None, LookingForBoundary, ReadingHeaders,
    ReadingField, SkippingFile,
}
```

## 4. Key APIs and Entry Points

### WafCore Request Processing

```rust
impl WafCore {
    // Primary entry point with full request data
    pub async fn check_request_full(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
        ua: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&SiteBotConfig>,
        _ctx: Option<&RequestServices>,
    ) -> WafDecision

    // Simplified entry point
    pub async fn check_request(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        ua: Option<&str>,
    ) -> WafDecision

    // Early check (pre-block list only)
    pub fn check_early(
        &self,
        client_ip: IpAddr,
        _path: &str,
        _cookies: Option<&str>,
        _ua: Option<&str>,
    ) -> WafDecision

    // Get streaming WAF for body inspection
    pub fn streaming(&self) -> Option<StreamingWafCore>
}
```

### StreamingWafCore Body Inspection

```rust
impl StreamingWafCore {
    // Set multipart boundary for form parsing
    pub fn set_multipart_boundary(&mut self, boundary: &str)
    
    // Scan a chunk of body data
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision
    
    // Get final detection result
    pub fn finalize(&self) -> Option<AttackDetectionResult>
    
    // Reset state for reuse
    pub fn reset(&mut self)
}
```

### AttackDetector Detection

```rust
impl AttackDetector {
    // Full request check
    pub async fn check_request(
        &self,
        client_ip: IpAddr,
        method: &http::Method,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> (Option<AttackDetectionResult>, u32)

    // Body-only checking
    pub fn check_body_only(&self, body: &[u8]) -> Option<AttackDetectionResult>
    
    // Multiple body fragments checking
    pub fn check_body_fragments(&self, fragments: &[&[u8]]) -> Option<AttackDetectionResult>
    
    // Fast-path check
    pub fn is_fast_path_safe(&self, inputs: &NormalizedInputs) -> bool
    
    // Create streaming WAF
    pub fn streaming(self: Arc<Self>) -> StreamingWafCore
}
```

### Rate Limiter API

```rust
impl RateLimiterManager {
    // Check rate limit for site/IP
    pub async fn check_rate_limit(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
    ) -> RateLimitResult

    // Check global rate limit
    pub fn check_global(&self) -> RateLimitResult

    // Acquire global connection permit
    pub async fn acquire_global_connection(&self) -> Result<GlobalConnectionPermit, ()>
}
```

### Connection Limiter API

```rust
impl ConnectionLimiter {
    // Try to acquire a connection token
    pub async fn try_acquire(
        &self,
        site_id: &str,
        client_ip: IpAddr,
    ) -> Result<ConnectionToken, ConnectionLimitError>

    // Acquire with queue fallback
    pub async fn acquire_with_queue(
        &self,
        site_id: &str,
        client_ip: IpAddr,
    ) -> Result<ConnectionToken, ConnectionLimitError>

    // Release a connection token
    pub fn release(&self, token: ConnectionToken)
}
```

## 5. Integration with Other Modules

### BlockStore Integration

The WAF integrates with `BlockStore` for IP blocking:
- Pre-blocked IPs checked via `check_block_store()` in request pipeline
- Violation tracker can block IPs via `store.block_ip()`
- Block store supports site-scoped blocking ("global" or site-specific)

### Challenge System Integration

`ChallengeManager` provides:
- JS/PoW challenge generation
- CSS honeypot challenges
- Session cookie management
- Challenge rate limiting

### Threat Intelligence (Mesh)

When `mesh` feature enabled:
- `ThreatIntelligenceManager` provides collaborative threat data
- `BehavioralIntelligenceManager` provides distributed behavioral analysis
- DHT-based threat feed sharing via `ThreatFeedClient`

### Metrics Integration

WAF reports metrics via `metrics` crate:
- `synvoid.ratelimit.global_limited`
- `synvoid.ratelimit.blackholed`
- `record_attack_type("Bots")` for bot detections

### Upload Validation

```rust
pub fn get_upload_validator() -> Option<Arc<crate::upload::UploadValidator>>
```

### RequestServices Context

Hot path optimization via `RequestServices`:
- Threaded through `WafContext` to avoid atomic contention
- Provides access to global Threat Intel and YARA rules

## 6. Feature Gates

### WAF Module Feature Gates

| Feature | Description |
|---------|-------------|
| `mesh` | Enables behavioral intelligence, DHT threat intel, mesh-based rule sharing |
| `flood-ebpf` | Linux-only eBPF-based SYN flood protection (requires Linux) |

### Configuration Feature Gates

```rust
// In Cargo.toml or features
[features]
default = ["mesh", "flood-ebpf"]
mesh = ["dep:crate::mesh"]
flood-ebpf = ["target_os=linux"]
```

### Test Mode Configuration

```rust
pub struct TestModeConfig {
    pub enabled: bool,
    pub ratelimit_off: bool,
    pub attack_off: bool,
    pub bot_off: bool,
    pub challenge_off: bool,
    pub flood_off: bool,
    pub asn_off: bool,
}
```

Allows disabling individual WAF components for testing.

## 7. Request Processing Flow

```
Request Received
       │
       ▼
┌──────────────────┐
│  check_block_store │ ──► Block/Drop if pre-blocked
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  check_rate_limits │ ──► Block(429) if rate limited
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  check_endpoint_block│ ──► Block if path blocked
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  check_honeypot    │ ──► Stall/Block on honeypot hit
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  check_bot_protection│ ──► Block/Tarpit/Challenge bots
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  check_flood_protection│ ──► Drop/RateLimit if flood
└──────────────────┘
       │
       ▼
┌──────────────────────────┐
│  Parallel Attack Detection │
│  ┌─────────────────────┐ │
│  │ Fast-path RegexSet  │ │
│  └─────────────────────┘ │
│  ┌─────────────────────┐ │
│  │ SQLi/XSS/PathTr...  │ │ (parallel via JoinSet)
│  └─────────────────────┘ │
│  ┌─────────────────────┐ │
│  │ Header Validation   │ │
│  └─────────────────────┘ │
└──────────────────────────┘
       │
       ▼
   WafDecision
```

## 8. Performance Considerations

### Hot Path Optimizations

1. **Atomic-free hot path**: `RequestServices` threaded through context
2. **Fast-path pre-screening**: 50+ regex patterns reject non-threatening requests quickly
3. **Parallel detection**: Heavy detectors run concurrently via `JoinSet`
4. **Thread-local buffers**: Normalizer uses thread-local buffers to avoid allocation
5. **Streaming body inspection**: Process body in chunks without full buffering

### Memory Management

1. **RingBuffer**: Efficient time-window tracking without GC pressure
2. **BufferPool**: Reusable buffers for normalized data
3. **DashMap**: Sharded maps reduce lock contention
4. **ArcSwapOption**: Lock-free optional sharing of AttackDetector

### Scaling for 1M+ RPS

1. **Site isolation**: Rate limits sharded per-site
2. **Shared memory**: Optional mmap-based rate limit state
3. **Connection queuing**: Backpressure instead of rejection
4. **Burst tokens**: Handle traffic spikes without hard limits

## 9. Configuration Reference

```rust
pub struct WafCoreConfig {
    rate_config: RateLimitConfigStore,      // IP and global limits
    memory_config: RateLimitMemoryConfig,    // Max entries, shards
    bot_config: BotDefaults,                 // Bot detection settings
    endpoint_config: BlockedDefaults,        // Blocked paths
    waf_config: WafConfig,                   // General WAF settings
    attack_detection_config: Option<AttackDetectionConfig>,
    threat_level_config: Option<ThreatLevelConfig>,
    ip_feed_config: Option<IpFeedConfig>,
    traffic_shaping_config: Option<TrafficShapingConfig>,
    bandwidth_config: BandwidthConfig,
}
```

Key AttackDetectionConfig settings:
- `paranoia_level`: Higher = more detection, more false positives
- `strict_normalization`: Enable null-byte/zero-width detection
- `max_request_body_size`: Limit body inspection size
- `anomaly_scoring.enabled`: Cumulative scoring across detectors

