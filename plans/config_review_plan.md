# Config Architecture Review Plan

## Verified Correct

### ConfigManager Location and Structure
- **ConfigManager** is correctly located at `crates/synvoid-config/src/lib.rs:113-119` (struct definition) and `lib.rs:121-241` (impl block)
- The struct contains: `main: MainConfig`, `sites: HashMap<String, SiteConfig>`, `sites_dir: PathBuf`, `config_dir: PathBuf`, and private `site_filenames: HashMap<String, PathBuf>`
- This matches the documented hierarchy exactly

### ConfigManager Methods
- `load_main()` - line 132-138: loads server-wide configuration
- `load_site()` - line 140-150: loads single domain config
- `discover_sites()` - line 152-198: auto-discovers all `*.toml` in `sites/` directory, returns `Vec<(String, Result<SiteConfig, String>)>`
- `reload_site()` / `reload_all()` - line 206-241: hot-reload support
- `get_site()` - line 200-204: domain-based lookup

### MainConfig Structure
- `MainConfig` in `main_config.rs:73-143` correctly contains all documented fields
- Feature-gated fields present: `icmp_filter` (line 127), `dns` (line 132), `mesh` (line 134)
- All documented fields present: `server`, `fallback`, `admin`, `logging`, `metrics`, `tokio`, `http`, `http3`, `tls`, `defaults`, `threat_level`, `ip_feeds`, `rule_feed`, `yara_feed`, `rate_limit_memory`, `proxy_limits`, `blocklist_limits`, `tcp`, `udp`, `tarpit`, `persistence`, `traffic_shaping`, `security`, `static_config`, `tunnel`, `plugins`, `serverless`, `upgrade`, `overseer`, `process_manager`, `supervisor`, `honeypot_port`, `mimes`

### SiteConfig Structure
- `SiteConfig` in `site/mod.rs:68-128` correctly implements the documented hierarchy
- `site_id()` method at line 204-206: derives from `site.domains.first()`
- `app_server_config()` method at line 208-261: propagates `SiteAppServerConfig` to `AppServerConfig`
- All documented fields present: `site`, `ratelimit`, `blocked`, `bot`, `honeypot_probe`, `error_pages`, `css_challenge`, `whitelist`, `worker_pool`, `logging`, `proxy`, `tcp`, `udp`, `tarpit`, `attack_detection`, `upload`, `auth`, `r#static`, `security`, `security_headers`, `traffic_shaping`, `grpc`, `websocket`, `tunnel`, `app_server`, `serverless`, `serverless_only`, `image_poison`, `file_manager`

### AppServerConfig Propagation
- `SiteAppServerConfig` in `site/app_server.rs:5-93`: all fields are `Option<T>`
- `AppServerConfig` in `app_server.rs:6-32`: all fields have concrete types with defaults
- `app_server_config()` method correctly propagates all fields with proper defaults
- `require_hashes` field correctly propagated at `site/mod.rs:259`

### Feature-Gated Compilation
- Documented features in `Cargo.toml`: `dns = []`, `icmp-filter = []`, `mesh = ["dep:ed25519-dalek", "dep:utoipa"]`, `rkyv = []`
- Code correctly uses `#[cfg(feature = "dns")]`, `#[cfg(feature = "mesh")]`, `#[cfg(feature = "icmp-filter")]`
- Core configuration always available regardless of features

### Serialization Strategy
- **TOML** for configuration files (confirmed via `toml::from_str` usage)
- **rkyv** available as optional feature for zero-copy network serialization
- **serde** derive macros for all config structs (confirmed)
- **schemars** + **utoipa** for OpenAPI documentation generation (confirmed via imports and `JsonSchema`/`ToSchema` derives)

### Config Propagation Pattern
- Pattern correctly documented at lines 260-266
- When adding new fields to `SiteAppServerConfig`, they must be propagated via `SiteConfig::app_server_config()` method
- Example pattern with `require_hashes` verified correct

### Key Config Files
| File | Verified |
|------|----------|
| `lib.rs` | ConfigManager at lines 113-241 |
| `main_config.rs` | MainConfig struct, `from_file()`, `validate()`, `default_config()` |
| `site/mod.rs` | SiteConfig, `app_server_config()` at lines 208-261 |
| `site/app_server.rs` | SiteAppServerConfig with all optional fields |
| `app_server.rs` | AppServerConfig with GranianInterface, GranianLogLevel, GranianLogFormat |
| `server.rs` | ServerConfig, FallbackConfig with validation |
| `defaults.rs` | All defaults (RateLimitDefaults, BotDefaults, HoneypotDefaults, etc.) |
| `dns/mod.rs` | DnsConfig, DnsMode, DnsRateLimitMode, DnsSecAlgorithm |
| `mesh.rs` | MeshConfig, MeshNodeRole, MeshRoutingConfig, MeshTlsConfig |
| `http.rs` | HttpConfig, Http3Config, TokioConfig |
| `tls.rs` | TlsConfig, AcmeConfig, ClientAuthConfig |
| `admin.rs` | AdminConfig, MetricsConfig, AdminCorsConfig |
| `logging.rs` | LoggingConfig, LogExporterConfig, LokiConfig, ElasticsearchConfig |
| `network.rs` | TcpDefaults, UdpDefaults, TarpitDefaults |
| `security.rs` | MainSecurityConfig, MainStaticConfig |
| `traffic.rs` | TrafficShapingConfig, ConnectionLimitsConfig, BandwidthConfig |
| `process.rs` | OverseerConfig, ProcessManagerConfig, SupervisorConfig, SupervisorConfigBuilder |
| `protection.rs` | ThreatLevelConfig, IpFeedConfig, RuleFeedConfig, YaraRuleFeedConfig |
| `limits.rs` | RateLimitMemoryConfig, ProxyLimitsConfig, BlocklistLimitsConfig |

---

## Discrepancies Found

### Minor Documentation Issue: Line Numbers
- The doc states "ConfigManager struct at lines 113-119, impl at lines 121-241"
- The struct definition is at lines 113-119 (correct)
- The impl block is at lines 121-242 (closes at line 242, not 241)
- This is a minor off-by-one but essentially correct

### Documentation References Non-existent Type
- The doc at line 260 mentions "GranianConfig (in `site/mod.rs`)" but no such type exists
- The actual pattern is: `SiteAppServerConfig` -> `AppServerConfig` via `SiteConfig::app_server_config()`
- The `app_server_config()` method returns `AppServerConfig`, not `GranianConfig`

---

## Bugs Identified

### Bug: AppServerConfig Default Port Mismatch (Low)
- **Location**: `crates/synvoid-config/src/app_server.rs:49`
- **Issue**: In `AppServerConfig::default()`, `port` defaults to `Some(8000)` and `host` defaults to `Some("127.0.0.1".to_string())`
- **Impact**: When a site has no explicit app_server config, these defaults will be used, but the documentation doesn't clarify that these are the Granian internal binding defaults (not the site listen port)
- **Severity**: Low - documentation issue rather than functional bug

---

## Suggested Improvements

### 1. Clarify GranianConfig Reference
The documentation at line 260 references "GranianConfig" which doesn't exist. This should be removed or clarified to say `AppServerConfig`.

### 2. Document `site_filenames` Field
The `ConfigManager` struct has a private `site_filenames: HashMap<String, PathBuf>` field that maps site IDs to their file paths for hot-reload purposes. This is an internal implementation detail that could be documented.

### 3. Add Validation Sequence Documentation
The document describes the validator pattern but doesn't specify the order in which validators are called in `MainConfig::validate()`. It would be helpful to document that validation proceeds in a specific order (server -> http -> tls -> threat_level -> fallback -> logging -> admin -> defaults -> tunnel).

### 4. Document Feature Interaction
When both `dns` and `mesh` features are enabled, `DnsConfig` can reference mesh settings. The interaction between feature-gated configs could be better documented.

### 5. Add Examples for Hot Reload
The ConfigManager supports `reload_site()` and `reload_all()` but no example is given of how these integrate with the reload signal handler.

### 6. Improve ConfigManager Load Sequence
Document that `load_main()` must be called before `discover_sites()` since site configs may reference settings from the main config.
