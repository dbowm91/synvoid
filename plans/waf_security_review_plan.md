# WAF & Security Review Plan

**Reviewed:** 2026-05-28
**Documents:** waf.md, waf_deep_dive.md, auth.md, challenge.md, captcha.md, block_store.md, tarpit.md, honeypot.md, upload.md, geoip.md, icmp_filter.md, integrity.md

## Verified Correct Items

- **WafDecision enum** (waf.md:264-279): All variants (`Pass`, `Block`, `Drop`, `Tarpit`, `Stall`, `Challenge`, `ChallengeWithCookie`) match `src/waf/mod.rs:60-74` exactly
- **WafConfig struct** (waf.md:306-316): All fields match `src/waf/mod.rs:102-112` exactly
- **TestModeConfig struct** (waf.md:552-560): All fields match `src/waf/mod.rs:77-85` exactly
- **BotDetector struct** (waf.md:103-112): All fields match `src/waf/bot.rs:8-16` exactly
- **BotDetectionResult enum** (waf.md:123-129): Variants match `src/waf/bot.rs` (Allowed/Blocked/Tarpit)
- **AttackType enum** (waf.md:292-296): All 14 variants match `src/waf/attack_detection/config.rs:189-204`
- **InputLocation enum** (waf.md:298-300): All 5 variants match `src/waf/attack_detection/config.rs:231-237`
- **AttackDetectionResult** (waf.md:285-290): Fields match `src/waf/attack_detection/config.rs:181-186`
- **StreamingWafCore** (waf.md:334-339): Fields match `src/waf/attack_detection/streaming.rs:16-21`
- **StreamingWafDecision** (waf.md:341-344): Variants match `src/waf/attack_detection/streaming.rs:10-13`
- **MultipartState** (waf.md:346-349): All 5 variants match `src/waf/attack_detection/streaming.rs:24-30`
- **check_request_full signature** (waf.md:359-372): Matches `src/waf/mod.rs:442-455`
- **check_request signature** (waf.md:376-382): Matches `src/waf/mod.rs:519-526`
- **check_early signature** (waf.md:385-391): Matches `src/waf/mod.rs:736-742`
- **Request processing pipeline order** (waf.md:567-616): Matches actual `check_request_full` flow in `src/waf/mod.rs:456-516`
- **FloodProtector line range** (waf_deep_dive.md:11): `src/waf/flood/mod.rs:225-367` — `FloodProtector` struct starts at line 225, file is 367 lines — CORRECT
- **FloodConfig defaults** (waf_deep_dive.md:15-16): `syn_rate_per_ip: 50`, `syn_rate_global: 10000` match `src/waf/flood/mod.rs:43-44`
- **UdpFloodProtector defaults** (waf_deep_dive.md:46): `udp_rate_per_ip: 1000`, `udp_rate_global: 100000` match `src/waf/flood/mod.rs:49-50`
- **Blackhole duration** (waf_deep_dive.md:47): `blackhole_duration_secs: 60` matches `src/waf/flood/mod.rs:52`
- **PatternDetector trait** (waf_deep_dive.md:62): Located at `src/waf/attack_detection/detector_common.rs:293` — CORRECT
- **StreamingWafCore chunk default** (waf_deep_dive.md:116): `DEFAULT_CHUNK_SIZE: usize = 4096` matches `src/waf/attack_detection/streaming.rs:6`
- **StreamingWafCore max buffered** (waf_deep_dive.md:119): `DEFAULT_MAX_BUFFERED_BYTES = 2 * 1024 * 1024` matches `src/waf/attack_detection/streaming.rs:7`
- **Trailing window size** (waf_deep_dive.md:117): `TRAILING_WINDOW_SIZE: usize = 512` matches `src/waf/attack_detection/streaming.rs:44`
- **BufferPool tiers** (waf_deep_dive.md:164): Documented as Small 4KB, Medium 64KB, Large 256KB, Jumbo 256KB+ — referenced correctly
- **flood-ebpf feature gate** (waf_deep_dive.md:203): `#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]` matches `src/waf/flood/mod.rs:5-6`
- **eBPF module path** (waf_deep_dive.md:205): `src/waf/flood/ebpf_flood.rs` exists
- **User struct** (auth.md:52-62): All fields match `src/auth/mod.rs:40-50`
- **UserRole enum** (auth.md:65-69): Variants match `src/auth/mod.rs:55-59`
- **Session struct** (auth.md:88-97): All fields match `src/auth/mod.rs:62-71`
- **SessionInfo struct** (auth.md:100-105): All fields match `src/auth/mod.rs:813-818`
- **AuthStore struct** (auth.md:122-126): All fields match `src/auth/mod.rs:74-78`
- **LoginLog struct** (auth.md:129-137): All fields match `src/auth/mod.rs:80-89`
- **AuthError enum** (auth.md:143-158): All variants match `src/auth/mod.rs` (InvalidCredentials, UserAlreadyExists, UserNotFound, InvalidUsername, PasswordTooShort, AccountLocked, HashingError)
- **AuthManager::new signature** (auth.md:169-174): Matches `src/auth/mod.rs:106-111`
- **min_password_length = 8** (auth.md:178): Matches `src/auth/mod.rs:160`
- **session_refresh_threshold = 0.5** (auth.md:179): Matches `src/auth/mod.rs:161`
- **CSRF constant-time comparison** (auth.md:432-435): `ct_eq()` at `src/auth/mod.rs:783` — CORRECT
- **File permissions 0o700/0o600** (auth.md:444-448): Match `src/auth/mod.rs:199-210`
- **MAX_SESSIONS_PER_USER = 5** (auth.md:343): Matches `src/auth/mod.rs:37`
- **Bcrypt DEFAULT_COST** (auth.md:454): Uses `bcrypt::DEFAULT_COST` at `src/auth/mod.rs:8`
- **Username validation** (auth.md:305-318): Exists at `src/auth/mod.rs:305-318` — min 1, max 64, no control chars — FIXED per AGENTS.md BUG-AUTH-1/2
- **Dummy password hash** (auth.md:264-276): `DUMMY_PASSWORD_HASH` at `src/auth/mod.rs:36` and `verify_dummy_password()` at line 26
- **ChallengeResult enum** (challenge.md:28-33): Variants match `src/challenge/mod.rs:22-27`
- **ChallengeType enum** (challenge.md:35-40): Variants match `src/challenge/mod.rs:30-36`
- **ChallengePriority enum** (challenge.md:42-49): All 6 variants match `src/challenge/mod.rs:39-47`
- **CaptchaManager struct** (captcha.md:18-22): Core fields match `src/captcha/mod.rs:10-14`
- **CaptchaResult enum** (captcha.md:29-34): Variants match `src/captcha/mod.rs` (Passed, Failed, Expired, Invalid)
- **PortHoneypotController** (honeypot.md:25-31): Exists at `src/honeypot_port/controller.rs`
- **UnifiedHoneypotManager** (honeypot.md:41-43): Exists at `src/honeypot_unified/mod.rs`
- **ThreatLevel enum** (honeypot.md:52-54): Variants match `src/honeypot_unified/mod.rs:12-18`
- **TarpitManager::generate_page** (tarpit.md:43): Signature matches `src/tarpit/mod.rs:51`
- **TarpitManager::is_scraper_user_agent** (tarpit.md:44): Signature matches `src/tarpit/mod.rs:61`
- **TarpitManager::should_tarpit** (tarpit.md:45): Signature matches `src/tarpit/mod.rs:69`
- **UploadValidationError enum** (upload.md:55-62): Core variants exist in `src/upload/mod.rs:34-70` (but actual has more variants)
- **GeoIpManager struct** (geoip.md:19-25): Core fields exist in `src/geoip/mod.rs:19-28`
- **GeoIpResult enum** (geoip.md:33-37): Variants match `src/geoip/types.rs`
- **IntegrityMode enum** (integrity.md:27-31): Variants match `src/integrity/config.rs:8-13`
- **BlockStore sharded storage** (block_store.md:69): 64 shards confirmed at `src/block_store.rs:28`
- **BlockStore file permissions** (block_store.md:73): 0o600 claimed — needs verification (not found in block_store.rs directly, may be set externally)

## Discrepancies Found

### waf.md
- **waf.md:30-45** — WafCore struct is incomplete. Missing fields: `auth_manager: Arc<AuthManager>`, `attack_detection_config`, `block_store`, `config`, `whitelist`, `tarpit_generator`, `tarpit_defaults`, `probe_tracker`, `suspicious_word_tracker`, `upstream_error_tracker`, `request_services`, `trust_token_key`, `test_mode`, `honeypot_ban_duration_secs`. Actual struct at `src/waf/mod.rs:172-201` has ~30 fields vs documented ~15.
- **waf.md:180** — `SiteConnectionLimiter` described as "Per-site wrapper with site-specific limits" — **does not exist as a struct** in the codebase. Per-site limiting is handled directly within `ConnectionLimiter` via `site_connections: DashMap<String, DashMap<IpAddr, AtomicU32>>`.
- **waf.md:318-328** — WafCoreConfig struct is severely incomplete. Missing fields: `whitelist`, `block_store`, `auth_manager`, `probe_config`, `suspicious_words_config`, `upstream_errors_config`, `asn_scraping_config`, `geoip`, `data_dir`, `test_mode`, `tarpit_defaults`. Actual struct at `src/waf/mod.rs:148-170` has 22 fields vs documented ~11.
- **waf.md:394** — `streaming()` return type documented as `Option<StreamingWafCore>` — actual is also `Option<StreamingWafCore>` at `src/waf/mod.rs:755` — but the actual implementation internally calls `ad.clone().streaming()` which takes `Arc<Self>`, not `self: Arc<Self>` as documented.
- **waf.md:441** — `streaming(self: Arc<Self>)` documented as method on AttackDetector — actual at `src/waf/attack_detection/mod.rs` takes `self: Arc<Self>` — this is correct.
- **waf.md:543-547** — Feature gates documented as `default = ["mesh", "flood-ebpf"]` — this is **incorrect**. The actual default features are defined in `Cargo.toml` and `flood-ebpf` is NOT in the default feature set (it's Linux-only). The `mesh` feature is separate.

### waf_deep_dive.md
- **waf_deep_dive.md:24** — "SiteConnectionLimiter struct exists but is not instantiated as a separate entity" — **No such struct exists anywhere in the codebase.** The grep for `struct SiteConnectionLimiter` returned zero results. This is dead documentation referencing removed code.
- **waf_deep_dive.md:46** — UDP flood defaults: documented as "per-IP (1000/sec) and global (100,000/sec)" — actual defaults at `src/waf/flood/mod.rs:49-50` are `udp_rate_per_ip: 1000` and `udp_rate_global: 100000` — CORRECT.

### auth.md
- **auth.md:15** — "No feature gates" claim is correct — auth module has no `#[cfg(feature)]` attributes.
- **auth.md:420-424** — Challenge module sub-features `pow_enabled`, `css_enabled`, `mesh_pow_enabled`, `honeypot_enabled` are documented as "optional sub-features" — these are actually **config fields** on `ChallengeConfig`, NOT Cargo feature gates. The wording is misleading.
- **auth.md:490** — AuthManager instantiation shown "from `src/waf/mod.rs:399`" — actual instantiation is at `src/waf/mod.rs:396-405`. Line number off by 3.

### challenge.md
- **challenge.md:19-26** — ChallengeManager struct shows `rate_limiter: RateLimiter` field — **does not exist** in the actual struct at `src/challenge/mod.rs:54-67`. The actual struct has: `pow`, `mesh_pow`, `css`, `honeypot`, `cookie_name`, `theme`, `priority`, `max_attempts`, `rate_limit_window_secs`, `attempts`, `max_attempts_entries`, `use_mesh_pow_when_available`. Rate limiting is handled via an internal `attempts: RwLock<HashMap<IpAddr, ChallengeAttempt>>` field, not a separate `RateLimiter`.
- **challenge.md:59** — `generate_challenge_page(ip, app_path).await` — actual method signature not verified in the snippet but the documented signature looks plausible.
- **challenge.md:107** — `has_leading_zeros_ct()` for PoW verification — not verified in the files read. Needs source check.

### captcha.md
- **captcha.md:18-22** — `CaptchaManager` struct shows `challenges: Arc<RwLock<HashMap<String, CaptchaChallenge>>>` — actual at `src/captcha/mod.rs:11` uses `challenges: Arc<RwLock<CaptchaStore>>` where `CaptchaStore` wraps the HashMap. Different structure.
- **captcha.md:21** — `verification_window_secs: u64` — actual at `src/captcha/mod.rs:12` is `verification_window_secs: u32`. Type mismatch.
- **captcha.md:25** — `created_at: u64` — actual matches at `src/captcha/mod.rs:31`.
- **captcha.md:43** — `CaptchaManager::new(verification_window_secs)` — actual at `src/captcha/mod.rs:35` takes `verification_window_secs: u32` not `u64`.

### block_store.md
- **block_store.md:20-26** — BlockStore struct is **wrong**. Documented as `entries: Arc<RwLock<HashMap<IpAddr, BlockEntry>>>` but actual at `src/block_store.rs:78-87` uses `shards: Vec<RwLock<AHashMap<String, BlockEntry>>>` (64-shard concurrent map). Also missing fields: `enabled`, `persist_path`, `config`, `total_entries`, `shutdown_tx`.
- **block_store.md:28-36** — BlockEntry struct is **wrong**. Documented fields `ip: IpAddr`, `created_at: u64`, `expires_at: Option<u64>`, `site_scope: Option<String>` don't match actual at `src/block_store.rs:31-39`: `ip: String`, `blocked_at: u64`, `ban_expire_seconds: u64`, `site_scope: String` (not Option), `access_count: u64`, `last_access: u64`.
- **block_store.md:47** — `is_blocked(ip, site_scope) -> Option<BlockEntry>` — actual signature not shown in read but method exists.
- **block_store.md:69** — "64-shard concurrent hashmap" — CORRECT per `src/block_store.rs:28`.

### tarpit.md
- **tarpit.md:19-22** — TarpitManager struct shows `chain: MarkovChain` — actual at `src/tarpit/mod.rs:11` is `chain: Arc<RwLock<MarkovChain>>`. Missing `Arc<RwLock<>>` wrapper.
- **tarpit.md:24-29** — TarpitConfig struct shows `max_depth: usize`, `links_per_page: usize` — actual at `src/tarpit/mod.rs:17-21` uses `max_depth: u32`, `links_per_page: u32`. Also missing `enabled: bool` field.
- **tarpit.md:43** — `generate_page(current_depth, path_seed) -> String` — actual at `src/tarpit/mod.rs:51` is `generate_page(&self, current_depth: u32, path_seed: &str) -> String` — `current_depth` is `u32` not `usize`.
- **tarpit.md:63** — Lists "scrapy, curl, wget, python-requests" as scraper patterns — actual default at `src/tarpit/mod.rs:31-39` also includes "python-urllib", "aiohttp", "httpx".

### honeypot.md
- **honeypot.md:25-31** — PortHoneypotController struct is **wrong**. Documented as having `listeners`, `port_manager`, `responder_registry`, `intel_extractor`, `mesh_controller` — actual at `src/honeypot_port/controller.rs:6-9` has only `runner: Arc<RwLock<Option<Arc<PortHoneypotRunner>>>>` and `config: Arc<RwLock<HoneypotPortConfig>>`. The documented fields may exist on `PortHoneypotRunner` instead.
- **honeypot.md:42-43** — `profiles: HashMap<IpAddr, IpHoneypotProfile>` — actual `UnifiedHoneypotManager` uses `OnceLock` singleton pattern, internal structure not fully visible from mod.rs. Field type may differ.
- **honeypot.md:45-49** — IpHoneypotProfile struct shows `url_hits: AtomicU32`, `port_connections: AtomicU32`, `protocols_probed: RwLock<HashSet<String>>` — actual at `src/honeypot_unified/mod.rs:43-50` uses `AtomicU64` for both counters, `RwLock<Vec<String>>` for protocols (not HashSet), and has additional fields `ip: IpAddr` and `last_hit: AtomicU64`.

### upload.md
- **upload.md:20-24** — UploadValidator struct shows `yara_scanner: Option<YaraScanner>`, `sandbox: Option<Sandbox>` — actual at `src/upload/mod.rs:94-101` has `sandbox: Arc<Sandbox>`, `malware_scanner: Option<Arc<MalwareScanner>>`, `config: UploadConfig`, `reload_lock`, and conditional `yara_rules`. Different field names and types.
- **upload.md:26-32** — UploadConfig struct is incomplete. Actual config at `src/upload/config.rs` has many more fields than documented.
- **upload.md:41-46** — ValidationResult struct shows `mime_type: Option<String>`, `size: usize` — actual at `src/upload/mod.rs:73-78` has `mime_type: String` (not Option), `size: u64` (not usize).
- **upload.md:55-62** — UploadValidationError enum is incomplete. Missing variants: `InvalidMultipart`, `NoData`, `EmptyFilename`, `IoError`, `YaraError`, `SandboxError`. Actual at `src/upload/mod.rs:34-70` has 10 variants vs documented 6.

### geoip.md
- **geoip.md:19-25** — GeoIpManager struct is incomplete. Documented fields use bare types but actual at `src/geoip/mod.rs:19-28` wraps most in `Arc<RwLock<>>`: `lookup: Arc<RwLock<GeoIpLookup>>`, `blocked_countries: Arc<RwLock<HashSet<String>>>`, `allowed_countries: Arc<RwLock<HashSet<String>>>`, `last_update: Arc<RwLock<Option<u64>>>`. Also missing `config: Arc<GeoIpConfig>`, `is_enabled: bool`.

### icmp_filter.md
- **icmp_filter.md:39-46** — FilterBackend enum shows `PfBsd` variant — **does not exist**. Actual at `src/icmp_filter/traits.rs:30-37` has only: `Nftables`, `Ebpf`, `Pf`, `WindowsFirewall`, `Wfp`. No `PfBsd` variant. BSD support uses the same `Pf` backend.
- **icmp_filter.md:48-54** — BackendCapabilities struct uses short field names: `block`, `allow`, `rate_limit`, `type_code`, `interface` — actual at `src/icmp_filter/traits.rs:40-49` uses `supports_block`, `supports_allow`, `supports_rate_limit`, `supports_type_code_matching`, `supports_interface_filtering`, plus `requires_admin` and `is_enforcing` (not documented).
- **icmp_filter.md:62-67** — Platform table feature gates are **wrong**:
  - eBPF listed as `flood-ebpf` — actual is `icmp-ebpf` (per `src/icmp_filter/mod.rs:10`)
  - pf listed as `icmp-filter` — actual is `icmp-pf` (per `src/icmp_filter/mod.rs:13`)
  - Windows Firewall listed as `icmp-filter` — actual is `icmp-winfw` (per `src/icmp_filter/mod.rs:22`)
  - WFP listed as `icmp-filter` — actual is `icmp-wfp` (per `src/icmp_filter/mod.rs:25`)
- **icmp_filter.md:24-31** — IcmpFilterManager struct shows `backend: Option<Box<dyn IcmpFilter>>` — actual at `src/icmp_filter/mod.rs:57-70` has `filter: Box<dyn IcmpFilter>` (not Option) when a backend is available, with cfg-gated conditional compilation.
- **icmp_filter.md:24-31** — IcmpFilterManager struct shows `config: IcmpFilterConfig` — actual struct has additional fields beyond what's visible in the snippet.
- **icmp_filter.md:34-37** — IcmpFilterFactory trait shows `create(config: &IcmpFilterConfig)` — actual at `src/icmp_filter/traits.rs:137` is `create(&self, config: IcmpFilterConfig)` (takes ownership, not reference).
- **icmp_filter.md:30** — IcmpFilter trait shows `update_config(&mut self, config: IcmpFilterConfig) -> Result<(), IcmpFilterError>` — actual at `src/icmp_filter/traits.rs:132` returns `Result<()>` (module's own Result type, not `Result<(), IcmpFilterError>`).
- **icmp_filter.md:59** — Section numbering: "## 2. Platform Backends" appears twice (lines 17 and 59). Duplicate section header.

### integrity.md
- **integrity.md:19-25** — IntegrityConfig struct is **severely incomplete**. Documented fields: `mode`, `key_exchange_url`, `session_ttl_secs`, `signing_headers`, `audit_pow_settings`. Actual at `src/integrity/config.rs:16-60` has 17+ fields including: `enabled`, `global_node_domains`, `max_concurrent_sessions`, `sign_request_headers`, `sign_response_headers`, `include_body_hash`, `include_method`, `include_path`, `include_query`, `cache_freshness_signed`, `audit_report_url`, `verify_on_edge`. `signing_headers` should be `sign_request_headers` + `sign_response_headers`. `audit_pow_settings` not found.
- **integrity.md:33-38** — SignedHttpMessage struct is **wrong**. Documented: `headers: HashMap`, `signature: Vec<u8>`, `public_key: Vec<u8>`, `timestamp: u64`. Actual at `src/integrity/protocol.rs:228-237`: `integrity_header: IntegrityHeader`, `method: Option<String>`, `path: Option<String>`, `query: Option<String>`, `headers: HashMap<String, String>`, `body_hash: Option<String>`, `signature: String`, `signed_at: i64`. Completely different structure.
- **integrity.md:40-44** — SessionKey struct is **wrong**. Documented: `key: Vec<u8>`, `expires_at: u64`, `node_id: String`. Actual at `src/integrity/protocol.rs:283` has `key: String` (base64, not `Vec<u8>`), `expires_at: u64`, `node_id: String`. `key` type mismatch.
- **integrity.md:91** — Feature gate `origin_key_exchange` — matches `src/integrity/mod.rs:58`: `#[cfg(feature = "origin_key_exchange")]` — CORRECT.

## Bugs Identified

- **[MEDIUM] BUG-WAF-DOC-1**: `SiteConnectionLimiter` referenced in waf.md:180 and waf_deep_dive.md:24 does not exist as a struct. The per-site limiting logic lives inside `ConnectionLimiter` directly. Documentation references dead/removed code.
- **[LOW] BUG-WAF-DOC-2**: icmp_filter.md `FilterBackend::PfBsd` variant does not exist. BSD uses the `Pf` backend. Documentation invents a non-existent enum variant.
- **[LOW] BUG-WAF-DOC-3**: icmp_filter.md feature gates are all wrong (`icmp-ebpf` not `flood-ebpf`, `icmp-pf` not `icmp-filter`, `icmp-winfw`/`icmp-wfp` not `icmp-filter`). Could mislead developers trying to enable features.
- **[LOW] BUG-WAF-DOC-4**: challenge.md documents `rate_limiter: RateLimiter` field on ChallengeManager that does not exist. Rate limiting is internal via `attempts` HashMap.
- **[LOW] BUG-WAF-DOC-5**: integrity.md `SignedHttpMessage` struct is completely wrong — missing `integrity_header`, `method`, `path`, `query`, `body_hash` fields, wrong types for `signature` and `timestamp`.

## Suggested Improvements

### Structural Accuracy
- **waf.md**: Rewrite WafCore and WafCoreConfig struct listings to match actual 30+ field structs. Consider using a table format instead of code blocks for large structs.
- **block_store.md**: Rewrite BlockStore and BlockEntry structs to match actual sharded storage design and correct field types.
- **integrity.md**: Rewrite SignedHttpMessage, SessionKey, and IntegrityConfig to match actual implementations. The documented versions are significantly outdated.
- **honeypot.md**: Rewrite PortHoneypotController to match actual runner-based architecture. Rewrite IpHoneypotProfile with correct atomic types and missing fields.
- **upload.md**: Rewrite UploadValidator, UploadConfig, ValidationResult, and UploadValidationError to match actual implementations.

### Feature Gate Accuracy
- **icmp_filter.md**: Fix all feature gate references. Replace `flood-ebpf` → `icmp-ebpf`, `icmp-filter` → `icmp-pf`/`icmp-winfw`/`icmp-wfp` as appropriate.
- **waf.md**: Remove or correct the `default = ["mesh", "flood-ebpf"]` feature gate documentation.

### Dead Code Cleanup
- **waf.md / waf_deep_dive.md**: Remove all references to `SiteConnectionLimiter`. It's been removed from the codebase.
- **icmp_filter.md**: Remove `PfBsd` variant from FilterBackend documentation.

### Type Accuracy
- **tarpit.md**: Fix `usize` → `u32` for `max_depth` and `links_per_page` in TarpitConfig.
- **captcha.md**: Fix `u64` → `u32` for `verification_window_secs`. Update CaptchaManager to show `CaptchaStore` wrapper.
- **upload.md**: Fix `Option<String>` → `String` for mime_type, `usize` → `u64` for size in ValidationResult.

### API Signature Accuracy
- **icmp_filter.md**: Fix `IcmpFilterFactory::create` signature: `config: &IcmpFilterConfig` → `config: IcmpFilterConfig` (ownership, not reference).
- **icmp_filter.md**: Fix `IcmpFilter::update_config` return type: `Result<(), IcmpFilterError>` → `Result<()>`.

### Documentation Completeness
- **auth.md**: Clarify that Challenge module "sub-features" are config fields, not Cargo feature gates.
- **honeypot.md**: Document the actual PortHoneypotRunner structure since the Controller delegates to it.
- **upload.md**: Add missing UploadValidationError variants (InvalidMultipart, NoData, EmptyFilename, IoError, YaraError, SandboxError).

## Stale Content

- **waf.md:180** — `SiteConnectionLimiter` description is stale; struct was removed.
- **waf_deep_dive.md:24** — `SiteConnectionLimiter` reference is stale; same as above.
- **icmp_filter.md:43** — `PfBsd` enum variant is stale; never existed in the enum.
- **integrity.md:33-44** — `SignedHttpMessage` and `SessionKey` structs are stale; both have been significantly refactored with `IntegrityHeader` and string-based signatures.
- **integrity.md:19-25** — `IntegrityConfig` is stale; the struct has nearly tripled in size since this was written.
- **block_store.md:20-36** — `BlockStore` and `BlockEntry` structs are stale; storage was changed from flat HashMap to 64-shard design, and BlockEntry fields were renamed.

## Cross-Reference Status

- **AGENTS.md: "SiteConnectionLimiter dead code"** — Documented as `src/waf/traffic_shaper/limiter.rs:306-346`. Verified: struct does not exist in the codebase at all. AGENTS.md status says "✅ FIXED 2026-05-27 - removed dead code" — confirmed removed. Architecture docs still reference it.
- **AGENTS.md: "BUG-AUTH-1/2 Username validation"** — Fixed at `src/auth/mod.rs:305-318`. Verified: validation exists (min 1, max 64, no control chars). auth.md does not document this validation.
- **AGENTS.md: "BUG-WAF-3 SiteConnectionLimiter dead code"** — Fixed. Architecture docs still reference removed code.
- **AGENTS.md: "StreamingWafCore trailing window logic"** — Fixed. Verified at `src/waf/attack_detection/streaming.rs:44,129-134`. waf_deep_dive.md correctly describes trailing window.
- **AGENTS.md: "max_failed_attempts default mismatch"** — Fixed. WafCore uses 3, auth.md documents 3 — consistent.
- **AGENTS.md: "request_body_size double assignment"** — Fixed. Not relevant to architecture docs.
- **AGENTS.md: "CSRF validation constant-time comparison"** — Verified at `src/auth/mod.rs:783`. auth.md correctly documents this.
- **AGENTS.md: "Audit log file permissions"** — Verified at `src/auth/mod.rs:199-210`. auth.md correctly documents 0o700/0o600.
