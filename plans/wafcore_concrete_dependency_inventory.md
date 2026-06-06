# WafCore Concrete Dependency Inventory

> Generated: 2026-06-05
> Purpose: Catalog every concrete root-crate dependency in `WafCore` and `WafCoreConfig` structs, plus root-owned types in WAF submodules.

---

## 1. `WafCoreConfig` Fields

| # | Field | Type | Defined In | Trait in `traits.rs`? | Can Replace Now? | Needs New Trait? | Root-Owned? |
|---|-------|------|-----------|----------------------|-----------------|-----------------|-------------|
| 1 | `rate_config` | `RateLimitConfigStore` | `src/waf/mod.rs:65` (root) | No | N/A | No | **Yes** — root-owned wrapper |
| 2 | `memory_config` | `RateLimitMemoryConfig` | `crates/synvoid-config/src/limits.rs:6` (crate) | No | No | No (config DTO) | No — crate-owned |
| 3 | `bot_config` | `BotDefaults` | `crates/synvoid-config/src/defaults.rs:253` (crate) | No | No | No (config DTO) | No — crate-owned |
| 4 | `endpoint_config` | `BlockedDefaults` | `crates/synvoid-config/src/defaults.rs:219` (crate) | No | No | No (config DTO) | No — crate-owned |
| 5 | `waf_config` | `WafConfig` | `synvoid-waf/src/primitives.rs:46` | No | No | No (config DTO) | No — crate-owned |
| 6 | `whitelist` | `Vec<String>` | std | No | No | No (plain data) | N/A |
| 7 | `block_store` | `Option<Arc<BlockStore>>` | `src/block_store.rs:78` (root) | `BlockListStore` | **Yes** — wrap in `ErasedBlockStore` | No | **Yes** — concrete root type |
| 8 | `attack_detection_config` | `Option<AttackDetectionConfig>` | `synvoid-waf/src/attack_detection/config.rs:56` | No | No | No (config DTO) | No — crate-owned |
| 9 | `auth_manager` | `Option<Arc<AuthManager>>` | `src/auth/mod.rs:91` (root) | No | No | **Yes** (Auth service) | **Yes** — concrete root type |
| 10 | `threat_level_config` | `Option<ThreatLevelConfig>` | `crates/synvoid-config/src/protection.rs:8` (crate) | No | No | No (config DTO) | No — crate-owned |
| 11 | `ip_feed_config` | `Option<IpFeedConfig>` | `crates/synvoid-config/src/protection.rs:230` (crate) | No | No | No (config DTO) | No — crate-owned |
| 12 | `probe_config` | `Option<HoneypotProbingDefaults>` | `crates/synvoid-config/src/defaults.rs:535` (crate) | No | No | No (config DTO) | No — crate-owned |
| 13 | `suspicious_words_config` | `Option<SuspiciousWordsConfig>` | `crates/synvoid-config/src/defaults.rs:614` (crate) | No | No | No (config DTO) | No — crate-owned |
| 14 | `upstream_errors_config` | `Option<UpstreamErrorsConfig>` | `crates/synvoid-config/src/defaults.rs:657` (crate) | No | No | No (config DTO) | No — crate-owned |
| 15 | `traffic_shaping_config` | `Option<TrafficShapingConfig>` | `crates/synvoid-config/src/traffic.rs:85` (crate) | No | No | No (config DTO) | No — crate-owned |
| 16 | `bandwidth_config` | `BandwidthConfig` | `crates/synvoid-config/src/traffic.rs:33` (crate) | No | No | No (config DTO) | No — crate-owned |
| 17 | `asn_scraping_config` | `Option<AsnScrapingConfig>` | `crates/synvoid-config/src/defaults.rs:401` (crate) | No | No | No (config DTO) | No — crate-owned |
| 18 | `geoip` | `Option<Arc<GeoIpManager>>` | `crates/synvoid-geoip/src/manager.rs:15` | `GeoIpLookup` | **Yes** — wrap in `ErasedGeoIp` | No | **Yes** — concrete external crate type |
| 19 | `data_dir` | `Option<PathBuf>` | std | No | No | No (plain data) | N/A |
| 20 | `test_mode` | `TestModeConfig` | `synvoid-waf/src/primitives.rs:21` | No | No | No (config DTO) | No — crate-owned |
| 21 | `tarpit_defaults` | `Option<TarpitDefaults>` | `crates/synvoid-config/src/network.rs:254` (crate) | No | No | No (config DTO) | No — crate-owned |

---

## 2. `WafCore` Fields

| # | Field | Type | Defined In | Trait in `traits.rs`? | Can Replace Now? | Needs New Trait? | Root-Owned? |
|---|-------|------|-----------|----------------------|-----------------|-----------------|-------------|
| 1 | `rate_limiter` | `RateLimiterManager` | `src/waf/ratelimit.rs:27` (root — `RateLimiterState` alias) | No | No | **Yes** (Rate limiting service) | **Yes** — concrete root type |
| 2 | `bot_detector` | `BotDetector` | `synvoid-waf/src/bot.rs:8` | No | No | No | No — crate-owned |
| 3 | `endpoint_blocker` | `EndpointBlockerManager` | `synvoid-waf/src/endpoints/blocker.rs:17` | No | No | No | No — crate-owned |
| 4 | `sensitive_endpoint_manager` | `SensitiveEndpointManager` | `synvoid-waf/src/endpoints/sensitive.rs:12` | No | No | No | No — crate-owned |
| 5 | `error_page_manager` | `ErrorPageManager` | `src/waf/endpoints.rs` (root) | No | No | **Yes** (Error page service) | **Yes** — concrete root type |
| 6 | `challenge_manager` | `ChallengeManager` | `src/challenge/mod.rs:30` (root) | `ChallengeService` | Partial — trait has minimal API | **Yes** (full challenge lifecycle) | **Yes** — concrete root type |
| 7 | `auth_manager` | `Arc<AuthManager>` | `src/auth/mod.rs:91` (root) | No | No | **Yes** (Auth service) | **Yes** — concrete root type |
| 8 | `attack_detector` | `ArcSwapOption<AttackDetector>` | `synvoid-waf/src/attack_detection/mod.rs:51` | No | No | No | No — crate-owned (wrapped) |
| 9 | `attack_detection_config` | `ArcSwapOption<AttackDetectionConfig>` | `synvoid-waf/src/attack_detection/config.rs:56` | No | No | No (config DTO) | No — crate-owned |
| 10 | `block_store` | `Option<Arc<BlockStore>>` | `src/block_store.rs:78` (root) | `BlockListStore` | **Yes** — use `ErasedBlockStore` | No | **Yes** — concrete root type |
| 11 | `config` | `WafConfig` | `synvoid-waf/src/primitives.rs:46` | No | No | No (config DTO) | No — crate-owned |
| 12 | `whitelist` | `Arc<HashSet<IpAddr>>` | std | No | No | No (plain data) | N/A |
| 13 | `tarpit_generator` | `Arc<MarkovChain>` | `synvoid-tarpit` (crate) | No | No | No | No — crate-owned |
| 14 | `tarpit_defaults` | `TarpitDefaults` | `crates/synvoid-config/src/network.rs:254` (crate) | No | No | No (config DTO) | No — crate-owned |
| 15 | `threat_level` | `Option<Arc<ThreatLevelManager>>` | `src/waf/threat_level/mod.rs:116` (root) | `ThreatLevelProvider` | Partial — trait only has `get_threat_level()` | **Yes** (full threat level lifecycle) | **Yes** — concrete root type |
| 16 | `violation_tracker` | `Option<Arc<ViolationTracker>>` | `synvoid-waf/src/violation_tracker.rs:67` | No | No | No | No — crate-owned |
| 17 | `ip_feed` | `Option<Arc<IpFeedManager>>` | `src/waf/ip_feed.rs:56` (root) | No | No | **Yes** (IP feed service) | **Yes** — concrete root type |
| 18 | `probe_tracker` | `Option<Arc<ProbeTracker>>` | `synvoid-waf/src/probe_tracker.rs:117` | No | No | No | No — crate-owned |
| 19 | `suspicious_word_tracker` | `Option<Arc<SuspiciousWordTracker>>` | `synvoid-waf/src/probe_tracker.rs:493` | No | No | No | No — crate-owned |
| 20 | `upstream_error_tracker` | `Option<Arc<UpstreamErrorTracker>>` | `synvoid-waf/src/probe_tracker.rs:641` | No | No | No | No — crate-owned |
| 21 | `traffic_shaper` | `Option<Arc<GlobalTrafficShaper>>` | `src/waf/traffic_shaper/global.rs:10` (root) | No | No | **Yes** (Traffic shaping service) | **Yes** — concrete root type |
| 22 | `connection_limiter` | `Option<Arc<ConnectionLimiter>>` | `synvoid-waf/src/traffic_shaper/limiter.rs:12` | No | No | No | No — crate-owned |
| 23 | `asn_tracker` | `Option<Arc<AsnTracker>>` | `src/waf/asn_tracker.rs:58` (root) | No | No | **Yes** (ASN tracking service) | **Yes** — concrete root type |
| 24 | `test_mode` | `TestModeConfig` | `synvoid-waf/src/primitives.rs:21` | No | No | No (config DTO) | No — crate-owned |
| 25 | `honeypot_ban_duration_secs` | `u64` | std | No | No | No (plain data) | N/A |
| 26 | `request_services` | `ArcSwapOption<RequestServices>` | `src/worker/context.rs:11` (root) | `WafRequestServices` | Partial — trait only has `site_id()` | **Yes** (full request context) | **Yes** — concrete root type |
| 27 | `flood_protector` | `Option<Arc<FloodProtector>>` | `synvoid-waf/src/flood/mod.rs:127` | No | No | No | No — crate-owned |
| 28 | `trust_token_key` | `[u8; 32]` | std | No | No | No (plain data) | N/A |

---

## 3. WAF Submodule Root Dependencies

### 3.1 `src/waf/threat_level/mod.rs`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `collector` | `Arc<ThreatMetricsCollector>` | `src/waf/threat_level/collector.rs` | **Yes** |
| 2 | `learner` | `Arc<BaselineLearner>` | `src/waf/threat_level/baseline.rs` | **Yes** |
| 3 | `scorer` | `Arc<ThreatScorer>` | `src/waf/threat_level/scorer.rs` | **Yes** |
| 4 | `history` | `Arc<ThreatHistory>` | `src/waf/threat_level/persistence.rs` | **Yes** |
| 5 | `sql_history` | `Option<Arc<SqliteHistory>>` | `src/waf/threat_level/persistence/sqlite.rs` | **Yes** |
| 6 | `persistence` | `Arc<BaselinePersistence>` | `src/waf/threat_level/persistence.rs` | **Yes** |
| 7 | `scale_tx` | `broadcast::Sender<ThreatLevel>` | `tokio` | N/A (std) |
| 8 | `config` | `ThreatLevelConfigExtended` | `src/waf/threat_level/mod.rs:23` | **Yes** (root-defined DTO) |

**External crate deps**: `parking_lot`, `serde`, `tokio`

### 3.2 `src/waf/violation_tracker.rs`

Re-exports from `synvoid_waf::violation_tracker::*` — no root-owned types.

### 3.3 `src/waf/probe_tracker.rs`

Re-exports from `synvoid_waf::probe_tracker::*` — no root-owned types.

### 3.4 `src/waf/ip_feed.rs`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `IpFeedManager` | `IpFeedManager` | `src/waf/ip_feed.rs:56` | **Yes** |
| 2 | `blocked_networks` | `Arc<RwLock<Vec<BlockedNetwork>>>` | `src/waf/ip_feed.rs:19` (root enum) | **Yes** |
| 3 | `blocked_ips` | `Arc<RwLock<HashSet<IpAddr>>>` | std | N/A |
| 4 | `config` | `IpFeedConfig` | `crates/synvoid-config/src/protection.rs:230` | No — crate-owned |
| 5 | `client` | `HttpClient` | `src/http_client/mod.rs` (root) | **Yes** — root HTTP client |

**External crate deps**: `parking_lot`, `serde`, `tokio`
**Root deps**: `crate::http_client::{create_simple_http_client, get_with_timeout, HttpClient}`, `crate::utils::safe_unix_timestamp`

### 3.5 `src/waf/asn_tracker.rs`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `AsnTracker` | `AsnTracker` | `src/waf/asn_tracker.rs:58` | **Yes** |
| 2 | `asn_windows` | `DashMap<u32, AsnWindowState>` | root struct | **Yes** |
| 3 | `asn_cache` | `RwLock<lru_time_cache::LruCache<IpAddr, u32>>` | external crate | No — external |
| 4 | `config` | `AsnScrapingConfig` | `crates/synvoid-config/src/defaults.rs:401` | No — crate-owned |
| 5 | `geoip` | `Option<Arc<GeoIpManager>>` | `crates/synvoid-geoip/src/manager.rs` | **Yes** — concrete external crate type |
| 6 | `block_store` | `Option<Arc<BlockStore>>` | `src/block_store.rs:78` | **Yes** — concrete root type |
| 7 | `whitelisted_asns` | `Arc<RwLock<HashSet<u32>>>` | std | N/A |
| 8 | `last_cleanup` | `parking_lot::Mutex<Instant>` | external crate | No — external |

**Root deps**: `crate::block_store::BlockStore`, `crate::geoip::GeoIpManager`, `crate::geoip::types::AsnInfo`, `crate::waf::ratelimit::core::AtomicSlidingWindow`, `crate::metrics::record_attack_type`, `crate::utils::{current_timestamp, safe_unix_timestamp}`

### 3.6 `src/waf/attack_detection/` (root `mod.rs`)

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `AttackDetector` | `AttackDetector` | `src/waf/attack_detection/mod.rs:64` | **Yes** (but mirrors `synvoid_waf` type) |
| 2 | `config` | `AttackDetectionConfig` | `synvoid-waf/src/attack_detection/config.rs` | No — crate-owned |
| 3 | All `*Detector` fields | `Arc<*Detector>` | `src/waf/attack_detection/*.rs` | **Yes** (root copies) |
| 4 | `fast_path_detector` | `Option<regex::RegexSet>` | `regex` crate | No — external |
| 5 | `behavioral_engine` | `Arc<BehavioralEngine>` | `src/waf/attack_detection/behavioral.rs` | **Yes** |
| 6 | `behavioral_intel` | `Option<Arc<BehavioralIntelligenceManager>>` | `src/mesh/` | **Yes** (mesh-gated) |

**Root deps**: `crate::metrics::health::{SystemHealthMonitor, HealthState}`, `crate::mesh::behavioral_intel` (cfg-gated)

### 3.7 `src/waf/traffic_shaper/`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `GlobalTrafficShaper` | `GlobalTrafficShaper` | `src/waf/traffic_shaper/global.rs:10` | **Yes** |
| 2 | `config` | `GlobalTrafficShapingConfig` | `crates/synvoid-config/src/traffic.rs:112` | No — crate-owned |
| 3 | `bandwidth_config` | `BandwidthConfig` | `crates/synvoid-config/src/traffic.rs:33` | No — crate-owned |
| 4 | `ingress_bucket` | `Arc<AsyncTokenBucket>` | `synvoid-waf/src/traffic_shaper/async_bucket.rs` | No — crate-owned |
| 5 | `egress_bucket` | `Arc<AsyncTokenBucket>` | `synvoid-waf/src/traffic_shaper/async_bucket.rs` | No — crate-owned |
| 6 | `SiteTrafficShaper` | `SiteTrafficShaper` | `src/waf/traffic_shaper/global.rs:182` | **Yes** |

**Root deps**: `crate::metrics::bandwidth::get_global_bandwidth_tracker_or_log`, `crate::waf::ThreatLevelManager`

### 3.8 `src/block_store.rs`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `BlockStore` | `BlockStore` | `src/block_store.rs:78` | **Yes** |
| 2 | `shards` | `Vec<RwLock<AHashMap<String, BlockEntry>>>` | root | **Yes** |
| 3 | `config` | `DenyListLimitsConfig` | `synvoid_config::limits::BlocklistLimitsConfig` (re-export) | No — crate-owned |
| 4 | `mitigation_provider` | `ArcSwapOption<SizedMitigationProvider>` | root wrapper around `dyn MitigationProvider` | **Yes** |
| 5 | `persist_tx` | `Option<mpsc::Sender<PersistRequest>>` | tokio | N/A (std) |

**Root deps**: `crate::config::DenyListLimitsConfig`, `crate::utils::collections::AHashMap`, `crate::utils::safe_unix_timestamp`, `crate::waf::mitigation::{MitigationProvider, SizedMitigationProvider}`

### 3.9 `src/auth/`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `AuthManager` | `AuthManager` | `src/auth/mod.rs:91` | **Yes** |
| 2 | `data_dir` | `PathBuf` | std | N/A |
| 3 | `store` | `Arc<RwLock<AuthStore>>` | root | **Yes** |
| 4 | `write_tx` | `mpsc::Sender<...>` | tokio | N/A (std) |
| 5 | `flush_requested` | `DrainFlag` | `src/` (root) | **Yes** |

**External crate deps**: `bcrypt`, `chrono`, `serde`, `subtle`, `tokio`, `uuid`
**Root deps**: `crate::DrainFlag`

### 3.10 `src/challenge/`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `ChallengeManager` | `ChallengeManager` | `src/challenge/mod.rs:30` | **Yes** |
| 2 | `pow` | `Option<PowManager>` | `src/challenge/pow.rs` | **Yes** |
| 3 | `mesh_pow` | `Option<MeshPowManager>` | `src/challenge/mesh_pow.rs` | **Yes** |
| 4 | `css` | `Option<CssManager>` | `src/challenge/css.rs` | **Yes** |
| 5 | `honeypot` | `HoneypotTracker` | `src/challenge/honeypot.rs` | **Yes** |
| 6 | `theme` | `ThemeConfig` | `src/theme.rs` (root) | **Yes** |
| 7 | `attempts` | `RwLock<HashMap<IpAddr, ChallengeAttempt>>` | root | **Yes** |

**External crate deps**: `parking_lot`
**Root deps**: `crate::theme::{ChallengePageTemplate, ThemeConfig}`, `crate::utils::current_timestamp`
**Crate deps**: `synvoid_challenge::pow`, `synvoid_challenge::types`

### 3.11 `src/geoip/` (external crate: `synvoid-geoip`)

`GeoIpManager` is in `crates/synvoid-geoip/src/manager.rs`. It's an external crate dependency, not root-owned.

**Used by**: `WafCoreConfig.geoip`, `AsnTracker.geoip`

### 3.12 `src/tarpit/`

| # | Field/Type | Concrete Type | Defined In | Root-Owned? |
|---|-----------|---------------|-----------|-------------|
| 1 | `TarpitManager` | `TarpitManager` | `src/tarpit/mod.rs:10` | **Yes** |
| 2 | `chain` | `Arc<RwLock<MarkovChain>>` | `synvoid-tarpit` (crate) | No — crate-owned |
| 3 | `config` | `TarpitConfig` | `synvoid-tarpit` (crate) | No — crate-owned |
| 4 | `TarpitHandler` | `TarpitHandler` | `src/tarpit/handler.rs` | **Yes** (root wrapper) |

**Crate deps**: `synvoid_tarpit::{MarkovChain, TarpitConfig}`, `synvoid_waf` (re-exported)
**Root deps**: `parking_lot`

### 3.13 `src/upload/`

Re-exports from `synvoid_upload::*` — no root-owned types.

---

## 4. Summary: Root-Owned Types Requiring Trait Abstraction

### Already has trait (can be replaced now)

| Root Type | Existing Trait | Action |
|-----------|---------------|--------|
| `BlockStore` | `BlockListStore` + `ErasedBlockStore` | Replace `Option<Arc<BlockStore>>` with `Option<ErasedBlockStore>` |
| `GeoIpManager` | `GeoIpLookup` + `ErasedGeoIp` | Replace `Option<Arc<GeoIpManager>>` with `Option<ErasedGeoIp>` |

### Needs new trait

| Root Type | Proposed Trait | Reason |
|-----------|---------------|--------|
| `AuthManager` | `AuthService` | Session management, CSRF, login — core auth abstraction |
| `ChallengeManager` | Expand `ChallengeService` | Current trait is minimal (only `should_issue_challenge`/`build_challenge`) |
| `ThreatLevelManager` | Expand `ThreatLevelProvider` | Current trait only has `get_threat_level()` — needs `record_attack()`, `get_throttling_multiplier()`, etc. |
| `RateLimiterManager` | `RateLimitService` | Rate limit checking, per-IP and global |
| `IpFeedManager` | `IpFeedService` | IP feed lookup (`is_blocked`) |
| `AsnTracker` | `AsnTrackingService` | ASN-based distributed scraper detection |
| `GlobalTrafficShaper` | `TrafficShapingService` | Bandwidth limiting, monthly caps |
| `ErrorPageManager` | `ErrorPageService` | Error page rendering |
| `RequestServices` | Expand `WafRequestServices` | Current trait only has `site_id()` — needs full context |
| `TarpitHandler` | Already has `TarpitService` | Expand if needed |
| `RequestServices` (worker context) | Expand `WafRequestServices` | Needs threat_intel, upload_validator, yara_rules, plugin_manager |

### Config DTOs (not candidates for trait abstraction)

These are plain data transfer objects from `synvoid-config` crate — they should remain as-is:

- `IpRateLimitConfig`, `GlobalRateLimitConfig`, `RateLimitMemoryConfig`
- `BotDefaults`, `BlockedDefaults`, `AsnScrapingConfig`
- `WafConfig`, `TestModeConfig`, `AttackDetectionConfig`
- `ThreatLevelConfig`, `IpFeedConfig`, `HoneypotProbingDefaults`
- `SuspiciousWordsConfig`, `UpstreamErrorsConfig`
- `TrafficShapingConfig`, `BandwidthConfig`, `GlobalTrafficShapingConfig`
- `TarpitDefaults`, `DenyListLimitsConfig` (re-export of `BlocklistLimitsConfig`)

### Plain data (no abstraction needed)

- `HashSet<IpAddr>`, `Vec<String>`, `Option<PathBuf>`, `u64`, `[u8; 32]`
