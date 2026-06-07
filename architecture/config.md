# SynVoid Configuration Module Architecture

## Table of Contents

1. [Purpose and Responsibility](#1-purpose-and-responsibility)
2. [Key Submodules and Their Responsibilities](#2-key-submodules-and-their-responsibilities)
3. [Major Data Structures and Types](#3-major-data-structures-and-types)
4. [Key APIs and Entry Points](#4-key-apis-and-entry-points)
5. [Configuration Validation](#5-configuration-validation)
6. [Site-Based Configuration](#6-site-based-configuration)
7. [Security Defaults](#7-security-defaults)
8. [Feature Gates](#8-feature-gates)

---

## 1. Purpose and Responsibility

The `synvoid-config` crate (`crates/synvoid-config/`) provides strongly-typed configuration structs for all SynVoid subsystems. It handles:

- **Main Configuration**: Global settings for the entire SynVoid server
- **Site Configuration**: Per-domain/site settings with granular control
- **Configuration Discovery**: Automatic loading of site configs from filesystem
- **Validation**: Comprehensive validation of all configuration values
- **Defaults**: Sensible defaults for all configuration options
- **Serialization**: TOML parsing with JSON Schema and OpenAPI (utoipa) support

### Design Philosophy

- **Type Safety**: All configuration values are strongly typed
- **Fail-Safe Defaults**: Secure defaults that work out-of-the-box
- **Hierarchical Validation**: Nested validation of all configuration sections
- **Feature Gated Components**: Optional features like DNS and Mesh have compile-time gates

---

## 2. Key Submodules and Their Responsibilities

### Core Configuration Modules

| Module | File | Responsibility |
|--------|------|----------------|
| **main_config** | `main_config.rs` | `MainConfig` struct - root configuration for entire server |
| **site** | `site/mod.rs` | `SiteConfig` struct - per-site configuration with 17 sub-components |
| **defaults** | `defaults.rs` | `DefaultsConfig` - default values for sites (rate limits, challenges, etc.) |
| **validation** | `validation.rs` | `ConfigValidationError` and `parse_size_string()` utility |

### Infrastructure Modules

| Module | File | Responsibility |
|--------|------|----------------|
| **admin** | `admin.rs` | Admin API, metrics, CORS, rate limiting, token management |
| **security** | `security.rs` | IPC signing, global security headers, static file worker |
| **process** | `process.rs` | Overseer, Supervisor, ProcessManager configurations |
| **http** | `http.rs` | HTTP server settings, HTTP/3, Tokio runtime |
| **tls** | `tls.rs` | TLS/SSL settings, ACME, client authentication |
| **logging** | `logging.rs` | Logging exporters (Elasticsearch, Loki), request body logging |

### Networking Modules

| Module | File | Responsibility |
|--------|------|----------------|
| **network** | `network.rs` | TCP/UDP defaults, Tarpit configuration |
| **tunnel** | `tunnel.rs` | WireGuard VPN, QUIC tunnel, mesh integration |
| **mesh** | `mesh.rs` | DHT/mesh networking, node identity, routing |

### Protection & Traffic Modules

| Module | File | Responsibility |
|--------|------|----------------|
| **protection** | `protection.rs` | Threat levels, IP feeds, YARA rules, ban durations |
| **traffic** | `traffic.rs` | Traffic shaping, connection limits, bandwidth caps |
| **dns** | `dns/mod.rs` | DNS server (feature-gated), DNSSEC, rate limiting |

### Site-Specific Submodules (in `site/`)

| Module | File | Responsibility |
|--------|------|----------------|
| **listen** | `site/listen.rs` | `SiteInfo`, `SiteListenConfig`, `UpstreamConfig` |
| **security** | `site/security.rs` | CORS, cookies, basic auth, TLS verification, headers |
| **proxy** | `site/proxy.rs` | Upstream proxy, caching, headers, retry config |
| **backend** | `site/backend.rs` | Backend location routing, FastCGI, PHP |
| **attack_detection** | `site/attack_detection.rs` | SQLi, XSS, RFI, SSRF, path traversal detection |
| **ratelimit** | `site/ratelimit.rs` | Per-site rate limits, endpoint overrides |
| **static_files** | `site/static_files.rs` | Static file serving, file manager |
| **traffic_shaping** | `site/traffic_shaping.rs` | Per-site traffic limits |
| **upload** | `site/upload.rs` | Upload configuration, allowed types |
| **error_pages** | `site/error_pages.rs` | Custom error pages, theming |
| **defensive** | `site/defensive.rs` | Bot detection, CSS/POW challenges |
| **network** | `site/network.rs` | Site-specific TCP/UDP, protocol filters |

---

## 3. Major Data Structures and Types

### MainConfig (Root Configuration)

```rust
pub struct MainConfig {
    pub server: ServerConfig,           // Server bind address, port
    pub fallback: FallbackConfig,        // Fallback behavior for unmatched hosts
    pub admin: AdminConfig,             // Admin API configuration
    pub logging: LoggingConfig,          // Logging setup
    pub metrics: MetricsConfig,          // Prometheus metrics
    pub tokio: TokioConfig,             // Tokio runtime worker threads
    pub http: HttpConfig,               // HTTP server settings
    pub tls: TlsConfig,                 // TLS settings
    pub http3: Http3Config,             // HTTP/3 settings
    pub defaults: DefaultsConfig,       // Default values for sites
    pub threat_level: ThreatLevelConfig, // Threat level scaling
    pub ip_feeds: IpFeedConfig,         // IP blocklist configuration
    pub rule_feed: RuleFeedConfig,      // Rule feed (feature-gated)
    pub yara_feed: YaraRuleFeedConfig,  // YARA rules feed
    pub rate_limit_memory: RateLimitMemoryConfig,
    pub proxy_limits: ProxyLimitsConfig,
    pub blocklist_limits: BlocklistLimitsConfig,
    pub tcp: TcpDefaults,               // TCP protocol defaults
    pub udp: UdpDefaults,               // UDP protocol defaults
    pub tarpit: TarpitDefaults,         // Tarpit configuration
    pub persistence: PersistenceConfig, // DHT persistence settings
    pub traffic_shaping: TrafficShapingConfig,
    pub security: MainSecurityConfig,   // IPC signing, security headers
    pub static_config: Option<MainStaticConfig>,
    pub tunnel: TunnelConfig,           // WireGuard + QUIC tunnel
    pub plugins: PluginConfig,          // WASM plugin configuration
    pub serverless: ServerlessConfig,   // Serverless function config
    pub upgrade: Option<UpgradeConfig>,
    pub icmp_filter: IcmpFilterConfig,  // Feature-gated ICMP filtering
    pub mimes: MimesConfig,
    pub dns: DnsConfig,                // Feature-gated DNS server
    pub mesh: Option<MeshConfig>,       // Feature-gated mesh networking
    pub supervisor_compat: SupervisorConfig,
    pub process_manager: ProcessManagerConfig,
    pub supervisor: SupervisorConfig,
    pub honeypot_port: HoneypotPortConfig,
}
```

### SiteConfig (Per-Site Configuration)

```rust
pub struct SiteConfig {
    pub site: SiteInfo,                 // Domains, listen config, upstream
    pub ratelimit: SiteRateLimitConfig,
    pub blocked: SiteBlockedConfig,
    pub bot: SiteBotConfig,
    pub honeypot_probe: SiteProbeConfig,
    pub error_pages: SiteErrorPagesConfig,
    pub css_challenge: SiteCssChallengeConfig,
    pub whitelist: SiteWhitelistConfig,
    pub worker_pool: SiteWorkerPoolConfig,
    pub logging: SiteLoggingConfig,
    pub proxy: SiteProxyConfig,
    pub tcp: SiteTcpConfig,
    pub udp: SiteUdpConfig,
    pub tarpit: SiteTarpitConfig,
    pub attack_detection: SiteAttackDetectionConfig,
    pub upload: SiteUploadConfig,
    pub auth: SiteAuthConfig,
    pub static: SiteStaticConfig,
    pub security: SiteSecurityConfig,
    pub security_headers: SiteSecurityHeadersConfig,
    pub traffic_shaping: SiteTrafficShapingConfig,
    pub grpc: SiteGrpcConfig,
    pub websocket: SiteWebSocketConfig,
    pub tunnel: SiteTunnelConfig,
    pub app_server: SiteAppServerConfig,
    pub serverless: Option<ServerlessConfig>,
    pub serverless_only: bool,
    pub image_rights: SiteImageRightsConfig,
    pub file_manager: SiteFileManagerConfig,
}
```

### ConfigManager (Configuration Loading & Discovery)

```rust
pub struct ConfigManager {
    pub main: MainConfig,
    pub sites: HashMap<String, SiteConfig>,
    pub sites_dir: PathBuf,
    pub config_dir: PathBuf,
    site_filenames: HashMap<String, PathBuf>,
}

impl ConfigManager {
    pub fn new(config_dir: PathBuf) -> Self
    pub fn load_main<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ...>
    pub fn load_site<P: AsRef<Path>>(&mut self, path: P) -> Result<String, ...>
    pub fn discover_sites(&mut self) -> Vec<(String, Result<SiteConfig, String>)>
    pub fn get_site(&self, domain: &str) -> Option<&SiteConfig>
    pub fn reload_site(&mut self, domain: &str) -> Result<(), String>
    pub fn reload_all(&mut self) -> Vec<(String, Result<(), String>)>
}
```

### Key Enumerations

| Enum | Location | Variants |
|------|----------|----------|
| `MeshNodeRole` | `mesh.rs:223` | Bitmask struct (not enum): `GLOBAL(0b010)`, `EDGE(0b001)`, `ORIGIN(0b100)`, `GLOBAL_EDGE(0b011)`, `GLOBAL_ORIGIN(0b110)`, `EDGE_ORIGIN(0b101)`, `ALL(0b111)`, `SERVERLESS_ORIGIN(0b1000)` — use `contains()` not `match` |
| `VpnAccessLevel` | `tunnel.rs:235` | `General`, `Admin` |
| `AcmeChallengeType` | `tls.rs:179` | `Http01`, `Dns01` |
| `DnsMode` | `dns/mod.rs:39` | `Standalone`, `Mesh` |
| `BandwidthLimitAction` | `traffic.rs:24` | `Block`, `Throttle` |

---

## 4. Key APIs and Entry Points

### Configuration Loading

```rust
// Load main configuration from TOML file
MainConfig::from_file("/etc/synvoid/main.toml") -> Result<MainConfig, Box<dyn Error + Send + Sync>>

// Load site configuration from TOML file
SiteConfig::from_file("/etc/synvoid/sites/example.com.toml") -> Result<SiteConfig, anyhow::Result>

// Create ConfigManager with default config
ConfigManager::new(config_dir: PathBuf) -> ConfigManager

// Discover and load all sites from sites directory
config_manager.discover_sites() -> Vec<(String, Result<SiteConfig, String>)>
```

### Configuration Validation

```rust
// Validate entire main configuration
main_config.validate() -> Result<(), ConfigValidationError>

// Validate site configuration
site_config.validate() -> Result<(), ConfigValidationError>

// Validate defaults
defaults_config.validate() -> Result<(), ConfigValidationError>
```

### Admin Token Resolution

```rust
// Resolve admin token from config or environment variable
admin_config.resolve_token() -> String
// Priority: 1) env var if set, 2) non-default token in config, 3) generate new
```

### Site-Specific Methods

```rust
// Get site ID (first domain)
site_config.site_id() -> String

// Get upstream for path (route matching)
upstream_config.get_upstream(path: &str) -> String

// Convert listen config to socket address
listen_config.to_socket_addr(default_port: u16) -> Option<SocketAddr>

// Generate AppServerConfig from SiteConfig
site_config.app_server_config() -> AppServerConfig
```

### Mesh Configuration Helpers

```rust
// Get node ID (from config or identity)
mesh_config.node_id() -> String

// Get router ID
mesh_config.router_id() -> String

// Get signing key
mesh_config.signing_key() -> Option<&[u8]>

// Check if mesh is enabled
tunnel_config.has_mesh() -> bool

// Check if node is global
tunnel_config.is_global_node() -> bool
```

---

## 5. Configuration Validation

### Validation Architecture

Configuration validation is hierarchical and comprehensive:

```
MainConfig.validate()
├── server.validate()
├── http.validate()
├── tls.validate()
│   └── acme.validate()
├── threat_level.validate()
├── fallback.validate()
├── logging.validate()
├── admin.validate()
│   └── (admin.token resolved before validation)
├── defaults.validate()
│   ├── ratelimit.validate()
│   ├── upload.validate()
│   ├── worker_pool.validate()
│   └── bot.validate()
├── tunnel.validate()
│   ├── vpn.validate()
│   └── quic.validate()
├── dns.validate()           [feature-gated]
└── mesh.validate()          [feature-gated]
```

### Key Validation Rules

#### Admin Configuration
- Port must be non-zero
- bcrypt_cost must be 12-15 (minimum recommended)
- Token must be at least 32 characters
- Token cannot be "changeme" in release builds
- Token cannot contain weak patterns (password, admin, qwerty, etc.)
- CORS wildcard triggers warning

#### Site Configuration
- At least one domain required
- Domain length must be <= 253 characters
- Default upstream must start with `http://`, `https://`, `tunnel:`, or `unix:`
- Route patterns cannot be empty
- Upstream for routes cannot be empty

#### HTTP Configuration
- header_read_timeout_secs > 0
- max_headers > 0
- max_request_size > 0
- max_connections > 0

#### TLS Configuration
- If enabled, must have cert_path OR acme.enabled
- If enabled, must have key_path OR acme.enabled
- Certificate file must exist
- Key file must exist

#### ACME Configuration
- Email must be set
- At least one domain must be specified
- Cache directory must be writable

### ConfigValidationError Structure

```rust
pub struct ConfigValidationError {
    pub field: String,   // Dot-notation path: "admin.token"
    pub message: String,  // Human-readable error message
}
```

---

## 6. Site-Based Configuration

### Site Discovery and Loading

Sites are stored in `{config_dir}/sites/` as TOML files. The naming convention is `{domain}.toml`.

```rust
// Automatic discovery in ConfigManager
let mut manager = ConfigManager::new(config_dir);
manager.discover_sites();  // Loads all *.toml files from sites/

// Manual site loading
manager.load_site("/path/to/site.toml")?;

// Reload on change
manager.reload_site("example.com")?;
```

### SiteConfig Structure

Each site has 28 configuration sections:

1. **site** (`SiteInfo`) - Domains, listen addresses, upstream
2. **ratelimit** (`SiteRateLimitConfig`) - Rate limit overrides
3. **blocked** (`SiteBlockedConfig`) - Blocked paths, methods
4. **bot** (`SiteBotConfig`) - Bot detection settings
5. **honeypot_probe** (`SiteProbeConfig`) - Honeypot probing detection
6. **error_pages** (`SiteErrorPagesConfig`) - Custom error pages
7. **css_challenge** (`SiteCssChallengeConfig`) - CSS challenge settings
8. **whitelist** (`SiteWhitelistConfig`) - IP/user-agent whitelists
9. **worker_pool** (`SiteWorkerPoolConfig`) - Worker pool config
10. **logging** (`SiteLoggingConfig`) - Site-specific logging
11. **proxy** (`SiteProxyConfig`) - Upstream proxy, caching, headers
12. **tcp** (`SiteTcpConfig`) - TCP-specific settings
13. **udp** (`SiteUdpConfig`) - UDP-specific settings
14. **tarpit** (`SiteTarpitConfig`) - Tarpit settings
15. **attack_detection** (`SiteAttackDetectionConfig`) - SQLi, XSS, etc.
16. **upload** (`SiteUploadConfig`) - Upload settings
17. **auth** (`SiteAuthConfig`) - Authentication settings
18. **static** (`SiteStaticConfig`) - Static file serving
19. **security** (`SiteSecurityConfig`) - Security settings
20. **security_headers** (`SiteSecurityHeadersConfig`) - Security headers
21. **traffic_shaping** (`SiteTrafficShapingConfig`) - Traffic limits
22. **grpc** (`SiteGrpcConfig`) - gRPC settings
23. **websocket** (`SiteWebSocketConfig`) - WebSocket settings
24. **tunnel** (`SiteTunnelConfig`) - Site tunnel settings
25. **app_server** (`SiteAppServerConfig`) - Granian app server
26. **serverless** - Serverless function config
27. **image_rights** - Image rights marking config
28. **file_manager** - File manager config

### Upstream Configuration

```rust
pub struct UpstreamConfig {
    pub default: String,                    // Default upstream URL
    pub routes: HashMap<String, String>,   // Path -> upstream mappings
    pub tunnel_mappings: HashMap<String, u16>,  // Tunnel identifier -> port
}

impl UpstreamConfig {
    pub fn get_upstream(&self, path: &str) -> String {
        // Route matching: first matching prefix wins
        for (route_prefix, upstream) in &self.routes {
            if path.starts_with(route_prefix) {
                return self.resolve_tunnel_upstream(upstream);
            }
        }
        self.resolve_tunnel_upstream(&self.default)
    }
}
```

Supported upstream schemes:
- `http://` - HTTP upstream
- `https://` - HTTPS upstream
- `tunnel:` or `tunnel://` - Tunnel-based upstream
- `unix:` - Unix socket upstream

### Fallback Site

```rust
impl SiteConfig {
    pub fn default_fallback_site(upstream: String) -> Self {
        SiteConfig {
            site: SiteInfo {
                domains: vec!["_fallback_".to_string()],
                upstream: UpstreamConfig {
                    default: upstream,
                    routes: HashMap::new(),
                    tunnel_mappings: HashMap::new(),
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }
}
```

---

## 7. Security Defaults

### IPC Security

```rust
pub struct MainSecurityConfig {
    #[serde(default)]
    pub more_clear_headers: Vec<String>,           // Additional headers to clear
    #[serde(default = "default_sanitize_forwarded")]
    pub sanitize_forwarded_headers: bool,           // Sanitize X-Forwarded-* headers
    #[serde(default = "default_global_security_headers")]
    pub global_security_headers: bool,             // Apply security headers globally
    #[serde(default = "default_ipc_enforce_signing")]
    pub ipc_enforce_signing: bool,                 // Enforce IPC message signing
    #[serde(default)]
    pub ipc_session_key_env: Option<String>,        // Environment variable for IPC key
    #[serde(default)]
    pub allow_insecure_ipc_key: bool,               // Allow insecure fallback
}
```

Defaults:
- `ipc_enforce_signing = true` (IPC signing enforced by default)
- `sanitize_forwarded_headers = true`
- `global_security_headers = true`

### Admin Token Security

- Minimum token length: 32 characters
- bcrypt cost: 12 (minimum recommended)
- Default token generation: 32+ character cryptographically random
- Environment variable support: `admin.token_env_var`
- Weak pattern detection: rejects tokens containing "changeme", "password", "admin", etc.

### TLS Defaults

```rust
pub struct TlsConfig {
    #[serde(default)]
    pub prefer_post_quantum: bool,       // Use hybrid post-quantum KEX
    #[serde(default = "default_tls_1_3_only")]
    pub tls_1_3_only: bool,              // TLS 1.3 only (no 1.2)
    #[serde(default)]
    pub enable_tls_12_fallback: bool,      // Allow fallback to TLS 1.2
    #[serde(default)]
    pub strict_protocol_validation: bool,
    // ... ACME support, client auth, etc.
}
```

Defaults:
- TLS 1.3 only enabled by default
- Post-quantum key exchange preferred

### Security Headers Defaults

```rust
pub struct SiteSecurityHeadersConfig {
    #[serde(default = "default_security_headers_enabled")]
    pub strict_transport_security: Option<String>,  // "max-age=31536000; includeSubDomains"
    #[serde(default)]
    pub content_security_policy: Option<String>,
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: Option<String>,    // "nosniff"
    #[serde(default = "default_x_xss_protection")]
    pub x_xss_protection: Option<String>,          // "0"
    #[serde(default)]
    pub referrer_policy: Option<String>,
    #[serde(default)]
    pub permissions_policy: Option<String>,
    // ... plus CORS, cookies, etc.
}
```

### Bot Detection Defaults

```rust
pub struct BotDefaults {
    #[serde(default = "default_block_ai")]
    pub block_ai_crawlers: bool,                    // Block AI crawlers by default
    #[serde(default = "default_true")]
    pub enable_css_honeypot: bool,                  // CSS challenge enabled
    #[serde(default)]
    pub enable_js_challenge: bool,
    #[serde(default)]
    pub known_bots_allow: Vec<String>,              // Google, Bing, Yandex, DuckDuckBot
    #[serde(default)]
    pub ai_crawlers_block: Vec<String>,             // GPTBot, ClaudeBot, etc.
    #[serde(default)]
    pub scraper_patterns: Vec<String>,             // curl, wget, python-requests, etc.
    pub challenge_window_secs: u64,                // Challenge window: 300 (5 min)
    pub js_difficulty: u8,                          // JS difficulty: 1
    pub challenge_max_attempts: u32,               // Max attempts: 5
}
```

### Blocked Paths Defaults

```rust
pub struct BlockedDefaults {
    pub paths: Vec<String>,         // [".env", ".git", "wp-login.php", ...]
    pub use_regex: bool,             // true (use regex by default)
    pub block_methods: Vec<String>, // ["GET", "POST"]
    pub block_response_code: u16,   // 403
}
```

---

## 8. Feature Gates

### Cargo.toml Features

```toml
[features]
dns = []           # DNS server module (disabled by default)
icmp-filter = []    # ICMP filtering module (disabled by default)
mesh = ["dep:ed25519-dalek"]  # Mesh networking (requires ed25519-dalek)
rkyv = []          # Rkyv serialization (optional)
```

### Feature-Gated Components

| Feature | Components Affected | Dependencies | Default |
|---------|-------------------|--------------|---------|
| `dns` | `dns/` module, `MainConfig.dns` | `hickory-proto`, `hickory-resolver`, `tokio-dstip`, `cryptoki`, `getrandom` | **On** |
| `icmp-filter` | `icmp_filter.rs`, `MainConfig.icmp_filter` | None | **Off** |
| `mesh` | `mesh.rs` module, `TunnelConfig.mesh`, `MeshConfig` | `ed25519-dalek`, `openraft` | **On** |
| `socket-handoff` | Socket handoff support | None | **On** |
| `erased_pool` | Erased connection pool | None | **On** |
| `swagger-ui` | OpenAPI Swagger UI | `utoipa-swagger-ui` | **On** |
| `wireguard` | WireGuard VPN tunnel | `defguard_boringtun` | **Off** |
| `flood-ebpf` | eBPF flood protection | `aya` | **Off** |
| `origin_key_exchange` | Origin key exchange protocol | None | **Off** |
| `audit` | Audit logging enhancements | None | **Off** |
| `post-quantum` | Post-quantum TLS | `rustls-post-quantum` | **Off** |
| `verify-pq` | Post-quantum verification | None | **Off** |
| `tun-rs` | TUN interface support | None | **Off** |
| `buffer` | Buffer pool (via synvoid-utils) | `synvoid-utils/buffer` | **Off** |
| `rkyv` | Rkyv serialization | None | **Off** |
| `macos-sandbox` | macOS sandbox enforcement | None | **Off** |
| `test-utils` | Test utilities | None | **Off** |
| `fastcgi_streaming` | Streaming FastCGI responses | None | **Off** |

### Feature-Gated Validation

```rust
// In MainConfig::validate()
#[cfg(feature = "dns")]
if self.dns.enabled && !cfg!(feature = "dns") {
    return Err(ConfigValidationError {
        field: "dns.enabled".to_string(),
        message: "DNS server configured but binary built without `dns` feature. Rebuild with `--features dns`.".to_string(),
    });
}

#[cfg(feature = "mesh")]
if self.mesh.is_some() && !cfg!(feature = "mesh") {
    return Err(ConfigValidationError {
        field: "mesh".to_string(),
        message: "Mesh configured but binary built without `mesh` feature. Rebuild with `--features mesh`.".to_string(),
    });
}
```

### Build Profiles

```bash
# Core profile (minimal - no DNS, no Mesh)
cargo check --no-default-features

# Mesh profile
cargo check --no-default-features --features mesh

# DNS profile
cargo check --no-default-features --features dns

# Full profile (all features)
cargo check --no-default-features --features mesh,dns
```

### Feature Dependencies

- `mesh` feature requires `ed25519-dalek` crate (for signing key operations)
- All features are mutually independent except mesh requires ed25519-dalek

---

## Appendix: Configuration Type Reference

### Type Aliases

```rust
pub type ConfigHandle = Arc<MainConfig>;  // Thread-safe shared config
```

### Serialization Support

- **serde**: Full Serialize/Deserialize support via `#[derive(Serialize, Deserialize)]`
- **JsonSchema**: JSON Schema generation via `schemars::JsonSchema`
- **utoipa**: OpenAPI documentation via `utoipa::ToSchema`

### Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `MIN_TOKEN_LENGTH` | 32 | `admin.rs:7` |
| `default_mesh_port` | 50051 | `mesh.rs:563` |
| `default_tls_port` | 443 | `tls.rs:61` |
| `default_dns_port` | 53 | `dns/mod.rs:144` |
| `default_wg_port` | 51820 | `tunnel.rs:87` |
| `default_quic_port` | 51821 | `tunnel.rs:209` |

---

## Appendix: File Structure

```
crates/synvoid-config/src/
├── lib.rs                  # Module exports, ConfigManager
├── main_config.rs          # MainConfig struct
├── defaults.rs             # DefaultsConfig, all default value structs
├── validation.rs            # ConfigValidationError
├── security.rs             # MainSecurityConfig, MainStaticConfig
├── admin.rs                # AdminConfig, MetricsConfig
├── http.rs                 # HttpConfig, Http3Config, TokioConfig
├── tls.rs                  # TlsConfig, AcmeConfig, ClientAuthConfig
├── tunnel.rs               # TunnelConfig, VPN, QUIC
├── mesh.rs                 # MeshConfig, NodeIdentity, MeshNodeRole
├── protection.rs           # ThreatLevel, IP feeds, YARA rules
├── traffic.rs              # TrafficShaping, connection limits
├── process.rs              # Overseer, Supervisor, ProcessManager
├── dns/
│   ├── mod.rs              # DnsConfig (feature-gated)
│   ├── dns_anycast.rs      # DNS anycast configuration
│   ├── dns_dnssec.rs       # DNSSEC configuration
│   ├── dns_encrypted.rs    # DNS over HTTPS/TLS
│   ├── dns_firewall.rs     # DNS firewall rules
│   ├── dns_mesh.rs         # DNS mesh integration
│   ├── dns_misc.rs         # DNS miscellaneous settings
│   ├── dns_rate_limit.rs   # DNS rate limiting
│   ├── dns_recursive.rs    # Recursive DNS configuration
│   ├── dns_settings.rs     # DNS server settings
│   └── dns_zones.rs        # DNS zone configuration
├── icmp_filter.rs          # ICMP filtering (feature-gated)
├── site/
│   ├── mod.rs              # SiteConfig, SiteInfo
│   ├── listen.rs           # SiteListenConfig, UpstreamConfig
│   ├── security.rs         # SiteSecurityConfig, CORS, cookies
│   ├── proxy.rs            # SiteProxyConfig
│   ├── backend.rs          # Backend configs
│   ├── ratelimit.rs        # SiteRateLimitConfig
│   ├── attack_detection.rs # SQLi, XSS, RFI detection configs
│   ├── static_files.rs     # Static file serving
│   ├── traffic_shaping.rs  # Per-site traffic shaping
│   ├── upload.rs           # Upload configuration
│   ├── error_pages.rs      # Error page theming
│   ├── defensive.rs        # Bot, honeypot configs
│   ├── network.rs          # Site network config
│   ├── protocol_features.rs # gRPC, WebSocket
│   ├── app_server.rs       # Granian app server
│   ├── misc.rs             # SiteImageRightsConfig (compat alias SiteImagePoisonConfig), SiteLogging, SiteWorkerPool configs
│   └── file_manager.rs     # File manager config
├── bandwidth.rs            # Bandwidth tracking config
├── geoip.rs                # GeoIP configuration
├── honeypot_port.rs        # Honeypot port config
├── limits.rs               # Rate limit memory, proxy limits
├── logging.rs              # Logging exporters
├── network.rs              # TCP/UDP defaults
├── plugins.rs              # Plugin configuration
├── serverless.rs           # Serverless function config
├── server.rs               # ServerConfig, FallbackConfig
├── theme.rs                # Theme configuration
├── upgrade.rs              # Upgrade configuration
└── upload.rs               # Upload defaults
```
