# Configuration Module Review Plan

## Overview

This document reviews the architecture document at `architecture/config_deep_dive.md` and verifies its claims against the actual source code in `crates/synvoid-config/` and `src/config.rs`.

---

## 1. Claims Verification

### Claim 1: ConfigManager Location (lib.rs lines 113-233)

**Status:** VERIFIED

**Code Location:** `crates/synvoid-config/src/lib.rs:113-233`

The `ConfigManager` struct is confirmed at lines 113-118:
```rust
pub struct ConfigManager {
    pub main: MainConfig,
    pub sites: HashMap<String, SiteConfig>,
    pub sites_dir: PathBuf,
    pub config_dir: PathBuf,
}
```

Methods verified:
- `load_main()` - lines 130-136
- `load_site()` - lines 138-146
- `discover_sites()` - lines 148-193
- `reload_site()` / `reload_all()` - lines 199-232
- `get_site()` - lines 195-197

---

### Claim 2: Feature-Gating Pattern (dns, icmp-filter, mesh)

**Status:** VERIFIED

**Code Location:** `crates/synvoid-config/Cargo.toml:33-37`

```toml
[features]
dns = []
icmp-filter = []
mesh = ["dep:ed25519-dalek", "dep:utoipa"]
rkyv = []
```

Confirmed in `main_config.rs`:
- DNS: `#[cfg(feature = "dns")]` lines 16-17, 131-132, 265-266
- Mesh: `#[cfg(feature = "mesh")]` lines 133-134, 167-175, 267-268
- ICMP-filter: `#[cfg(feature = "icmp-filter")]` lines 11-12, 125-127, 262-263

---

### Claim 3: Configuration Hierarchy (MainConfig structure)

**Status:** VERIFIED WITH DISCREPANCIES

**Code Location:** `crates/synvoid-config/src/main_config.rs:73-143`

The document lists the hierarchy at lines 47-67. Verified fields:

| Documented Field | Actual Field | Status |
|-----------------|-------------|--------|
| server: ServerConfig | server: ServerConfig | VERIFIED |
| fallback: FallbackConfig | fallback: FallbackConfig | VERIFIED |
| admin: AdminConfig | admin: AdminConfig | VERIFIED |
| logging: LoggingConfig | logging: LoggingConfig | VERIFIED |
| metrics: MetricsConfig | metrics: MetricsConfig | VERIFIED |
| http: HttpConfig | http: HttpConfig | VERIFIED |
| http3: Http3Config | http3: Http3Config | VERIFIED |
| tls: TlsConfig | tls: TlsConfig | VERIFIED |
| defaults: DefaultsConfig | defaults: DefaultsConfig | VERIFIED |
| threat_level: ThreatLevelConfig | threat_level: ThreatLevelConfig | VERIFIED |
| dns: DnsConfig | dns: DnsConfig [feature=dns] | VERIFIED |
| mesh: MeshConfig | mesh: Option<MeshConfig> [feature=mesh] | VERIFIED |
| tunnel: TunnelConfig | tunnel: TunnelConfig | VERIFIED |
| plugins: PluginConfig | plugins: PluginConfig | VERIFIED |
| process_manager: ProcessManagerConfig | process_manager: ProcessManagerConfig | VERIFIED |
| overseer: OverseerConfig | overseer: OverseerConfig | VERIFIED |
| supervisor: SupervisorConfig | supervisor: SupervisorConfig | VERIFIED |
| sites: HashMap<String, SiteConfig> | (part of ConfigManager, not MainConfig) | DOCUMENT ERROR |

**Discrepancy:** The document shows `sites: HashMap<String, SiteConfig>` under MainConfig, but `sites` is actually in `ConfigManager`, not `MainConfig`. The ConfigManager wraps MainConfig and adds site configs separately.

Additional verified MainConfig fields not in document hierarchy:
- tokio: TokioConfig (line 81)
- ip_feeds: IpFeedConfig (line 93)
- rule_feed: RuleFeedConfig (line 94)
- yara_feed: YaraRuleFeedConfig (line 96)
- rate_limit_memory: RateLimitMemoryConfig (line 98)
- proxy_limits: ProxyLimitsConfig (line 100)
- blocklist_limits: BlocklistLimitsConfig (line 102)
- tcp: TcpDefaults (line 104)
- udp: UdpDefaults (line 106)
- tarpit: TarpitDefaults (line 108)
- persistence: PersistenceConfig (line 110)
- traffic_shaping: TrafficShapingConfig (line 112)
- security: MainSecurityConfig (line 114)
- static_config: Option<MainStaticConfig> (line 116)
- serverless: ServerlessConfig (line 122)
- upgrade: Option<UpgradeConfig> (line 124)
- icmp_filter: IcmpFilterConfig [feature=icmp-filter] (line 127)
- mimes: MimesConfig (line 129)
- honeypot_port: HoneypotPortConfig (line 142)

---

### Claim 4: Site Config Hierarchy

**Status:** MOSTLY VERIFIED

**Code Location:** `crates/synvoid-config/src/site/mod.rs:68-128`

Most fields verified. Some discrepancies:

| Documented Field | Actual Field | Status |
|-----------------|-------------|--------|
| site_id: String | (derived from site.domains.first()) | VERIFIED (method at line 204-206) |
| site: SiteInfo | site: SiteInfo | VERIFIED |
| app_server: SiteAppServerConfig | app_server: SiteAppServerConfig | VERIFIED |
| ratelimit: SiteRateLimitConfig | ratelimit: SiteRateLimitConfig | VERIFIED |
| security: SiteSecurityConfig | security: SiteSecurityConfig | VERIFIED |
| security_headers: SiteSecurityHeadersConfig | security_headers: SiteSecurityHeadersConfig | VERIFIED |
| attack_detection: SiteAttackDetectionConfig | attack_detection: SiteAttackDetectionConfig | VERIFIED |
| proxy: SiteProxyConfig | proxy: SiteProxyConfig | VERIFIED |
| r#static: SiteStaticConfig | r#static: SiteStaticConfig | VERIFIED |
| upload: SiteUploadConfig | upload: SiteUploadConfig | VERIFIED |
| traffic_shaping: SiteTrafficShapingConfig | traffic_shaping: SiteTrafficShapingConfig | VERIFIED |
| grpc: SiteGrpcConfig | grpc: SiteGrpcConfig | VERIFIED |
| websocket: SiteWebSocketConfig | websocket: SiteWebSocketConfig | VERIFIED |
| tunnel: SiteTunnelConfig | tunnel: SiteTunnelConfig | VERIFIED |
| bot: SiteBotConfig | bot: SiteBotConfig | VERIFIED |
| honeypot_probe: SiteProbeConfig | honeypot_probe: SiteProbeConfig | VERIFIED |
| css_challenge: SiteCssChallengeConfig | css_challenge: SiteCssChallengeConfig | VERIFIED |
| error_pages: SiteErrorPagesConfig | error_pages: SiteErrorPagesConfig | VERIFIED |
| file_manager: SiteFileManagerConfig | file_manager: SiteFileManagerConfig | VERIFIED |
| blocked: SiteBlockedConfig | blocked: SiteBlockedConfig | VERIFIED |
| whitelist: SiteWhitelistConfig | whitelist: SiteWhitelistConfig | VERIFIED |
| worker_pool: SiteWorkerPoolConfig | worker_pool: SiteWorkerPoolConfig | VERIFIED |
| logging: SiteLoggingConfig | logging: SiteLoggingConfig | VERIFIED |
| tcp: SiteTcpConfig | tcp: SiteTcpConfig | VERIFIED |
| udp: SiteUdpConfig | udp: SiteUdpConfig | VERIFIED |
| tarpit: SiteTarpitConfig | tarpit: SiteTarpitConfig | VERIFIED |
| serverless: Option<ServerlessConfig> | serverless: Option<ServerlessConfig> | VERIFIED |
| serverless_only: bool | serverless_only: bool | VERIFIED |
| image_poison: SiteImagePoisonConfig | image_poison: SiteImagePoisonConfig | VERIFIED |

All documented fields are present and verified.

---

### Claim 5: App Server Configuration Propagation

**Status:** VERIFIED

**Code Location:** `crates/synvoid-config/src/site/app_server.rs:1-93` and `crates/synvoid-config/src/app_server.rs:1-161`

`SiteAppServerConfig` uses `Option` fields - VERIFIED (lines 4-54 in app_server.rs)

Propagation via `SiteConfig::app_server_config()` at `site/mod.rs:208-261` - VERIFIED

Default value examples:
- `enabled: false if not set` - line 212
- `app_path: empty if not set` - line 213
- `workers: 1 if not set` - line 219
- `blocking_threads: 4 if not set` - line 220
- `interface: Asgi if not set` - lines 214-218
- `require_hashes: false if not set` - line 259

---

### Claim 6: Serialization Strategy (TOML + rkyv + schemars + utoipa)

**Status:** VERIFIED

**Code Location:** `crates/synvoid-config/Cargo.toml:6-31`

- TOML: `toml = "0.8"` (line 10)
- serde: `serde = { version = "1", features = ["derive"] }` (line 7)
- schemars: `schemars = "0.8"` (line 8)
- utoipa: `utoipa = { version = "5", ... }` (line 9)
- rkyv: `rkyv = { package = "rkyv", version = "0.8", features = ["std", "alloc"] }` (line 19)

---

### Claim 7: ConfigManager Pattern (load_main, load_site, discover_sites, etc.)

**Status:** VERIFIED

**Code Location:** `crates/synvoid-config/src/lib.rs:120-233`

All documented methods verified with tests at lines 235-438.

---

### Claim 8: Validator Pattern (validate() method)

**Status:** VERIFIED

**Code Location:** Multiple files

Each config has a `validate()` method returning `Result<(), ConfigValidationError>`:
- MainConfig: `main_config.rs:181-209`
- SiteConfig: `site/mod.rs:191-202`
- ServerConfig: `server.rs:22-61`
- FallbackConfig: `server.rs:76-93`
- HttpConfig: `http.rs:103-130`
- TlsConfig: `tls.rs:70-108`
- LoggingConfig: `logging.rs:48-78`
- AdminConfig: `admin.rs:110-179`
- DnsConfig: `dns/mod.rs:175-205`
- SiteAppServerConfig: `site/app_server.rs:71-92`

---

## 2. Improvement Plan

### HIGH PRIORITY

#### 1. Documentation Error: sites HashMap Location

**Issue:** The Configuration Hierarchy diagram in the document shows `sites: HashMap<String, SiteConfig>` under MainConfig, but this is incorrect. The `sites` field is in `ConfigManager`, not `MainConfig`.

**Fix Location:** `architecture/config_deep_dive.md:64-67`

**Recommended Fix:** Update the diagram to show:
```
MainConfig (top-level, server-wide)
├── server: ServerConfig
...
└── sites: HashMap<String, SiteConfig>  # In ConfigManager, not MainConfig
```

Or clarify that ConfigManager contains both MainConfig and sites.

#### 2. Missing Fields in Hierarchy Diagram

**Issue:** The Configuration Hierarchy diagram omits several fields present in MainConfig:
- tokio: TokioConfig
- ip_feeds: IpFeedConfig
- rule_feed: RuleFeedConfig
- yara_feed: YaraRuleFeedConfig
- rate_limit_memory: RateLimitMemoryConfig
- proxy_limits: ProxyLimitsConfig
- blocklist_limits: BlocklistLimitsConfig
- tcp: TcpDefaults
- udp: UdpDefaults
- tarpit: TarpitDefaults
- persistence: PersistenceConfig
- traffic_shaping: TrafficShapingConfig
- security: MainSecurityConfig
- static_config: Option<MainStaticConfig>
- serverless: ServerlessConfig
- upgrade: Option<UpgradeConfig>
- icmp_filter: IcmpFilterConfig [feature=icmp-filter]
- mimes: MimesConfig
- honeypot_port: HoneypotPortConfig

**Fix Location:** `architecture/config_deep_dive.md:45-67`

**Recommended Fix:** Add all missing fields to the hierarchy diagram.

---

### MEDIUM PRIORITY

#### 3. ConfigManager site lookup uses exact domain match

**Issue:** `ConfigManager::get_site()` at `lib.rs:195-197` uses exact HashMap lookup (`self.sites.get(domain)`), but in practice, sites may have multiple domains. The `site_id()` method derives site_id from `site.domains.first()`, so domain-based lookup may not work for alias domains.

**Code Location:** `crates/synvoid-config/src/lib.rs:195-197`

```rust
pub fn get_site(&self, domain: &str) -> Option<&SiteConfig> {
    self.sites.get(domain)
}
```

**Recommended Fix:** Either:
1. Add a method to iterate sites and check if domain is in `site.domains` vec
2. Document that only primary domain works for lookup
3. Build reverse index by domain

#### 4. reload_site() relies on site.domains.first()

**Issue:** `ConfigManager::reload_site()` at `lib.rs:199-220` reconstructs the file path from `domains.first()`, which assumes the first domain matches the filename. If sites are stored under different filenames than their primary domain, reload will fail.

**Code Location:** `crates/synvoid-config/src/lib.rs:199-220`

```rust
if let Some(config) = self.sites.get(domain) {
    let domains = config.site.domains.clone();
    let filename = domains.first().map(|s| s.as_str()).unwrap_or("unknown");
    let path = self.sites_dir.join(format!("{}.toml", filename));
```

**Recommended Fix:** Store the original filename/path when loading the site config.

---

### LOW PRIORITY

#### 5. DNS Config uses custom DnsConfigError instead of ConfigValidationError

**Issue:** `dns/mod.rs:207-236` defines a custom `DnsConfigError` enum instead of using the unified `ConfigValidationError`. This inconsistency may make error handling more complex.

**Code Location:** `crates/synvoid-config/src/dns/mod.rs:207-236`

**Recommended Fix:** Consider using ConfigValidationError for consistency, or document why a custom error type is needed.

#### 6. No validate() call in SiteConfig::from_file()

**Issue:** `SiteConfig::from_file()` at `site/mod.rs:173-189` calls `config.validate()` before returning, which is correct. However, the document doesn't mention this validation occurs during loading.

**Status:** Behavior is correct, no change needed in code.

---

## 3. Bug Report

### MINOR BUG: reload_site() may fail for sites with filename mismatches

**Severity:** Minor

**Description:** If a site config file is named differently than its primary domain (e.g., file `example.com.toml` contains a config with `domains = ["www.example.com", "example.com"]`), the `reload_site()` method will look for `www.example.com.toml` which doesn't exist.

**Code Location:** `crates/synvoid-config/src/lib.rs:199-220`

**Steps to Reproduce:**
1. Create site config file as `example.com.toml`
2. Set `domains = ["www.example.com", "example.com"]`
3. Call `reload_site("example.com")` or `reload_site("www.example.com")`
4. Reload fails because it looks for `www.example.com.toml`

**Impact:** Low - Hot reload of site configs may fail in certain edge cases where domains and filenames don't align.

**Workaround:** Always name config files to match the primary (first) domain in the domains list.

---

### NO CRITICAL BUGS FOUND

The configuration module implementation is generally sound. The claims in the architecture document are mostly accurate, with the main issue being incomplete documentation (missing fields in hierarchy diagram) rather than implementation bugs.

---

## 4. Summary

| Category | Count |
|----------|-------|
| Claims Verified | 8 |
| Claims with Discrepancies | 1 (sites location) |
| High Priority Improvements | 2 |
| Medium Priority Improvements | 2 |
| Low Priority Improvements | 2 |
| Critical Bugs | 0 |
| Minor Bugs | 1 |

**Overall Assessment:** The configuration module is well-implemented and well-structured. The main issues are documentation gaps rather than implementation defects. The ConfigManager pattern, feature-gating, and validation patterns are all correctly implemented.
