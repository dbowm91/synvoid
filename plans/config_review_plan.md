# Configuration Module Review Plan

## Verified Correct Items

### ConfigManager Location and Structure
- **Correct**: ConfigManager struct is at `crates/synvoid-config/src/lib.rs:113-119`
- **Correct**: ConfigManager impl is at `crates/synvoid-config/src/lib.rs:121-241`
- **Correct**: ConfigManager methods (load_main, load_site, discover_sites, reload_site, reload_all, get_site) all exist with correct signatures

### Feature-Gating Pattern
- **Correct**: Cargo.toml features `dns = []`, `icmp-filter = []`, `mesh = ["dep:ed25519-dalek"]`, `rkyv = []`
- **Correct**: Core configuration (MainConfig, SiteConfig, ServerConfig) always compiles

### Configuration Hierarchy (MainConfig)
- **Correct**: Most fields in MainConfig match the document's hierarchy
- **Correct**: MainConfig::validate() calls validates on: server, http, tls, threat_level, fallback, logging, admin, defaults, tunnel
- **Correct**: Feature-gated fields (icmp_filter, dns, mesh) are properly gated with #[cfg(feature = "...")]

### SiteConfig Structure
- **Correct**: SiteConfig is per-domain configuration container
- **Correct**: `site_id()` method exists at line 204-206, returns first domain
- **Correct**: `app_server_config()` method exists at lines 208-261, correctly propagates SiteAppServerConfig to AppServerConfig

### AppServerConfig Propagation
- **Correct**: SiteAppServerConfig uses Option<T> fields (all optional)
- **Correct**: AppServerConfig has concrete defaults
- **Correct**: Propagation pattern correctly documented (unwrap_or defaults)

### Serialization Module (synvoid-utils)
- **Correct**: serialize(), deserialize(), deserialize_rkyv() functions exist
- **Correct**: serialize_bincode/deserialize_bincode exist as legacy wrappers
- **Correct**: serialized_size() exists

### Buffer Pool Architecture
- **Correct**: Tier sizes (Small 4KB, Medium 64KB, Large 256KB, Jumbo variable)
- **Correct**: Pool capacities (Small 512, Medium 256, Large 64, Jumbo 32)
- **Correct**: NUM_SHARDS = 8, TLS_CACHE_SIZE = 16
- **Correct**: PoolStats::reuse_rate() exists and calculates correctly
- **Correct**: GLOBAL_ALLOCATED_BYTES and GLOBAL_MEMORY_LIMIT exist as atomics
- **Correct**: PooledBuf struct exists with buf, tier, requested_size, allocated_size

### Defaults and Validation
- **Correct**: DefaultsConfig has validate() method at line 84-90
- **Correct**: DnsConfig has validate() method, calls validate on sub-components

---

## Stale/Incorrect Items

### 1. Key Files Table - Line Numbers Outdated
- **Document Line 31**: `lib.rs | ConfigManager struct at lines 113-119, impl at lines 121-241`
  - **Actual**: ConfigManager struct is at lines 113-119, impl at lines 121-241 - **CORRECT**
- **Document Line 32**: `main_config.rs | Root configuration container`
  - **Issue**: This file has been replaced by modular structure. MainConfig is now defined at `crates/synvoid-config/src/main_config.rs` but the MainConfig struct definitions are there and re-exported from lib.rs
  - **Not stale, just imprecise**

### 2. Configuration Hierarchy - Missing Fields
- **Document Lines 63-70**: Missing several fields present in actual MainConfig:
  - `icmp_filter: IcmpFilterConfig` - **[feature=icmp-filter]** - present at line 127 in main_config.rs
  - `mimes: MimesConfig` - present at line 129
  - `asn_scraping: AsnScrapingConfig` - present in defaults.rs
  - `honeypot_port: HoneypotPortConfig` - present at line 142
  - `fallback` is listed but `admin.token` resolution is missing

### 3. Configuration Hierarchy - Incorrect Field Ordering
- **Document Line 78**: `icmp_filter: IcmpFilterConfig  # [feature=icmp-filter]`
  - **Actual**: This field exists with correct feature gate, but is at line 125-127 in main_config.rs, not in sequential order as shown in document
  - The document shows it at position 78, but actual MainConfig has overseer, process_manager, supervisor before honeypot_port

### 4. Site Config Hierarchy - Missing Fields
- **Document Lines 100-107**: Several fields missing from SiteConfig:
  - `blocked: SiteBlockedConfig` - present in SiteConfig at line 74
  - `whitelist: SiteWhitelistConfig` - present at line 84
  - `worker_pool: SiteWorkerPoolConfig` - present at line 86
  - `logging: SiteLoggingConfig` - present at line 88
  - `tcp: SiteTcpConfig` - present at line 92
  - `udp: SiteUdpConfig` - present at line 94
  - `serverless: Option<ServerlessConfig>` - present at line 121
  - `serverless_only: bool` - present at line 123
  - `image_poison: SiteImagePoisonConfig` - present at line 125

### 5. DNS Config validate() Incomplete
- **Document Line 269**: "Each config has a validate() method returning Result<(), ConfigValidationError>"
- **Issue**: DnsConfig validates recursive at line 196, but **not** the `zones`, `limits`, `dot`, `doh`, `doq`, `rpz`, `dns64`, `prefetch`, `trust_anchors` fields (these are not called in validate())
- **Known Issue**: This matches "DnsConfig.validate() incomplete" from AGENTS.md - `recursive` validate() not called

### 6. Serialization Module Comments
- **Document Lines 237-253**: Table of serialization functions
- **Actual**: Some functions have slightly different signatures or documentation:
  - `deserialize_checked` and `serialize_checked` exist but are not in the document
  - The document doesn't mention `serialize_checked` and `deserialize_checked` which are useful for untrusted data

---

## Bugs Found

### BUG-DNS-1: DnsConfig.validate() Missing Sub-Component Validation
- **Location**: `crates/synvoid-config/src/dns/mod.rs:175-205`
- **Issue**: The validate() method doesn't call validate() on:
  - `zones` (DnsZonesConfig)
  - `limits` (DnsLimitsConfig)
  - `dot` (DnsDotConfig)
  - `doh` (DnsDohConfig)
  - `doq` (DnsDoqConfig)
  - `rpz` (DnsRpzConfig)
  - `dns64` (Dns64Config)
  - `prefetch` (DnsPrefetchConfig)
  - `trust_anchors` (TrustAnchorConfig)
- **Impact**: These sub-components could have invalid configuration that goes undetected
- **Severity**: Low (configuration defaults are usually safe)
- **Status**: Already listed as known issue in AGENTS.md

---

## Security Concerns

### SEC-1: Admin Token Default Warning
- **Location**: `crates/synvoid-config/src/main_config.rs:152-154`
- **Code**: 
  ```rust
  if config.admin.token.is_empty() || config.admin.token == "changeme" {
      config.admin.token = config.admin.resolve_token();
  }
  ```
- **Issue**: The `resolve_token()` method may generate a token or read from environment. If not properly configured, this could lead to predictable/admin access
- **Mitigation**: The code does warn when token is empty, and the default "changeme" is detected
- **Recommendation**: Document clearly that users must set admin.token or the token_env_var

### SEC-2: IPC Signing Warning (Informational)
- **Location**: `crates/synvoid-config/src/main_config.rs:156-164`
- **Issue**: When `ipc_enforce_signing` is enabled but no session key is configured, an ephemeral key is generated that will be lost on restart
- **Status**: This is an intentional warning, not a bug - behavior is correct

---

## Document Update Recommendations

### 1. Configuration Hierarchy Table (Lines 45-89)
**Correction Needed**: Update to match actual MainConfig field ordering and include all fields:
```diff
- ip_feeds: IpFeedConfig
- rule_feed: RuleFeedConfig
- yara_feed: YaraRuleFeedConfig
+ mimes: MimesConfig                    # MISSING FROM DOCUMENT
+ asn_scraping: AsnScrapingConfig       # MISSING FROM DOCUMENT (in defaults)
+ icmp_filter: IcmpFilterConfig  # [feature=icmp-filter]  # MISSING FROM DOCUMENT
+ honeypot_port: HoneypotPortConfig    # MISSING FROM DOCUMENT
```

### 2. Site Config Hierarchy (Lines 91-117)
**Correction Needed**: Update to include missing fields:
- `blocked: SiteBlockedConfig` (line 74)
- `whitelist: SiteWhitelistConfig` (line 84)
- `worker_pool: SiteWorkerPoolConfig` (line 86)
- `logging: SiteLoggingConfig` (line 88)
- `tcp: SiteTcpConfig` (line 92)
- `udp: SiteUdpConfig` (line 94)
- `serverless: Option<ServerlessConfig>` (line 121)
- `serverless_only: bool` (line 123)
- `image_poison: SiteImagePoisonConfig` (line 125)

### 3. Add Serialization Functions
**Addition Needed**: Document the following functions that exist but are not documented:
- `serialize_checked()` - for untrusted data (QUIC mesh)
- `deserialize_checked()` - for untrusted data

### 4. DnsConfig Validation Limitation
**Addition Needed**: Add note about DnsConfig.validate() limitations:
> **Note**: DnsConfig::validate() calls validate() on ratelimit, rrl, settings, dnssec, recursive, mesh (when Mesh mode), and anycast. However, zones, limits, dot, doh, doq, rpz, dns64, prefetch, and trust_anchors validation is not yet implemented (see BUG-DNS-1).

### 5. AppServerConfig Line Number Correction
**Correction**: The `app_server_config()` method is at lines 208-261 in site/mod.rs, which is correct. No change needed.

### 6. Buffer Pool Tier Capacities
**Addition**: The per-shard capacity calculations shown in the document (lines 193-196) are mathematically correct given 8 shards (Small 64, Medium 32, Large 8, Jumbo 4 per shard), but the document doesn't explain why 8 shards. Add note:
> The 8 shards reduce lock contention. Each shard maintains independent pools with independent Mutex<Vec<BytesMut>>.

### 7. Serialization "Why Postcard" Section
**Addition**: The document mentions "30% smaller serialized output" but the actual serialization.rs comments also mention "Drop-in replacement for bincode" which should be added to explain migration rationale.

---

## Summary

The configuration architecture document is **mostly accurate** with the following priorities:

1. **High Priority**: Update the Site Config Hierarchy table (missing fields: blocked, whitelist, worker_pool, logging, tcp, udp, serverless, serverless_only, image_poison)

2. **High Priority**: Update the Main Config Hierarchy table (missing fields: mimes, asn_scraping, icmp_filter, honeypot_port)

3. **Medium Priority**: Add note about DnsConfig.validate() incomplete sub-component validation

4. **Low Priority**: Add serialize_checked/deserialize_checked to serialization table

5. Document is otherwise well-structured and accurate. The ConfigManager location, buffer pool architecture, and serialization patterns are all correctly documented.
