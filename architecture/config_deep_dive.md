# Config & Utils Deep Dive

## Overview

This document covers the configuration library (`crates/synvoid-config/`) and utility library (`crates/synvoid-utils/`).

---

## 1. synvoid-config Crate (`crates/synvoid-config/`)

### Overview

The configuration library provides strongly-typed, feature-gated configuration structs for all SynVoid subsystems. It uses **TOML** for serialization with **schemars** for JSON schema generation and **utoipa** for OpenAPI documentation.

### Feature-Gating Pattern

```toml
[features]
dns = []
icmp-filter = []
mesh = ["dep:ed25519-dalek", "dep:utoipa"]
rkyv = []
```

Features are additive - DNS, ICMP-filter, and Mesh modules compile only when respective features are enabled. Core configuration (MainConfig, SiteConfig, ServerConfig) is always available.

### Key Files and Responsibilities

| File | Responsibility |
|------|----------------|
| `lib.rs` | ConfigManager struct at lines 113-119, impl at lines 121-241 |
| `main_config.rs` | Root configuration container for the entire SynVoid server |
| `site/mod.rs` | Site-level configuration (per-domain routing, upstream, listen) |
| `site/app_server.rs` | SiteAppServerConfig for Python ASGI/RSGI/WSGI site config |
| `app_server.rs` | Resolved AppServerConfig for worker processes; `GranianConfig` lives in `src/app_server/granian.rs` (the runtime type, not synvoid-config) |
| `server.rs` | Server socket binding and trusted proxy config |
| `defaults.rs` | Global default values for rate limits, bot challenges, honeypots, etc. |
| `dns/mod.rs` | DNS server configuration (recursive, zones, DNSSEC, mesh) |
| `mesh.rs` | Distributed mesh networking (DHT, peer-to-peer) |
| `http.rs` | HTTP protocol limits (header sizes, timeouts, max connections) |
| `tls.rs` | TLS/SSL termination, ACME Let's Encrypt, client certificates |
| `admin.rs` | Admin API, CORS, metrics endpoints |
| `logging.rs` | Structured logging exporters (Loki, Elasticsearch) |

### Configuration Hierarchy

```
ConfigManager (root container)
├── main: MainConfig               # Server-wide configuration
│   ├── server: ServerConfig       # Bind address, port, trusted proxies
│   ├── fallback: FallbackConfig   # 404 handling or proxy fallback
│   ├── admin: AdminConfig         # Admin API bind, token, CORS
│   ├── logging: LoggingConfig     # Log exporters
│   ├── metrics: MetricsConfig     # Prometheus metrics port
│   ├── tokio: TokioConfig         # Tokio runtime configuration
│   ├── http: HttpConfig           # HTTP protocol limits
│   ├── http3: Http3Config         # HTTP/3 QUIC settings
│   ├── tls: TlsConfig             # TLS certs, ACME
│   ├── defaults: DefaultsConfig   # Global default behaviors
│   ├── threat_level: ThreatLevelConfig
│   ├── ip_feeds: IpFeedConfig
│   ├── rule_feed: RuleFeedConfig
│   ├── yara_feed: YaraRuleFeedConfig
│   ├── rate_limit_memory: RateLimitMemoryConfig
│   ├── proxy_limits: ProxyLimitsConfig
│   ├── blocklist_limits: BlocklistLimitsConfig
│   ├── tcp: TcpDefaults
│   ├── udp: UdpDefaults
│   ├── tarpit: TarpitDefaults
│   ├── persistence: PersistenceConfig
│   ├── traffic_shaping: TrafficShapingConfig
│   ├── security: MainSecurityConfig
│   ├── static_config: Option<MainStaticConfig>
│   ├── tunnel: TunnelConfig        # WireGuard/QUIC VPN
│   ├── plugins: PluginConfig       # WASM plugin runtime
│   ├── serverless: ServerlessConfig
│   ├── upgrade: Option<UpgradeConfig>
│   ├── icmp_filter: IcmpFilterConfig  # [feature=icmp-filter]
│   ├── mimes: MimesConfig
│   ├── dns: DnsConfig              # [feature=dns]
│   ├── mesh: Option<MeshConfig>     # [feature=mesh]
│   ├── overseer: OverseerConfig    # Legacy process supervisor
│   ├── process_manager: ProcessManagerConfig
│   ├── supervisor: SupervisorConfig
│   └── honeypot_port: HoneypotPortConfig
├── sites: HashMap<String, SiteConfig>  # Per-domain configs (loaded from sites/ directory)
├── sites_dir: PathBuf
└── config_dir: PathBuf
```

### Site Config Hierarchy

```
SiteConfig (per-domain)
├── site_id(): String                   # Method: returns site.domains.first() (used as HashMap key in ConfigManager)
├── site: SiteInfo
│   ├── domains: Vec<String>           # Primary and alias domains
│   ├── listen: Vec<SiteListenConfig>  # Port, SSL, HTTP2/3, proxy protocol
│   └── upstream: UpstreamConfig        # Default + path-based routing, tunnel mappings
├── app_server: SiteAppServerConfig     # Python ASGI/RSGI/WSGI (optional)
├── ratelimit: SiteRateLimitConfig      # Per-site rate limits
├── security: SiteSecurityConfig        # Auth, whitelist, geoip
├── security_headers: SiteSecurityHeadersConfig
├── attack_detection: SiteAttackDetectionConfig
├── proxy: SiteProxyConfig              # Caching, headers, buffering
├── r#static: SiteStaticConfig          # Static file serving
├── upload: SiteUploadConfig
├── traffic_shaping: SiteTrafficShapingConfig
├── grpc: SiteGrpcConfig
├── websocket: SiteWebSocketConfig
├── tunnel: SiteTunnelConfig
├── bot: SiteBotConfig
├── honeypot_probe: SiteProbeConfig
├── css_challenge: SiteCssChallengeConfig
├── error_pages: SiteErrorPagesConfig
└── file_manager: SiteFileManagerConfig
```

### App Server Configuration Propagation

The `SiteAppServerConfig` uses `Option` fields (all optional in TOML), while `AppServerConfig` (the resolved type) has concrete defaults. Propagation occurs via `SiteConfig::app_server_config()`:

```rust
// Site level (all fields optional)
SiteAppServerConfig {
    enabled: Option<bool>,
    app_path: Option<String>,
    workers: Option<u32>,
    // ...
}

// Resolved for runtime (with defaults applied)
AppServerConfig {
    enabled: bool,           // false if not set
    app_path: String,        // empty if not set
    workers: u32,             // 1 if not set
    interface: GranianInterface,  // Asgi if not set
    blocking_threads: u32,   // 4 if not set
    // ...
}
```

### Serialization Strategy
- **TOML** for configuration files (human-readable)
- **rkyv** available as optional feature for zero-copy network serialization
- **serde** derive macros for all config structs
- **schemars** + **utoipa** for OpenAPI documentation generation

### AppServerConfig Default Values Bug (CFG-BUG-1)

**Issue:** `AppServerConfig` in `crates/synvoid-config/src/app_server.rs:49-50` has defaults that may not match production expectations:

```rust
port: Some(8000),
host: Some("127.0.0.1".to_string()),
```

**Note:** These defaults (port 8000 on localhost) are intentional for development mode but differ from typical production expectations where applications often bind to `0.0.0.0` or use different ports. When configuring `site.app_server`, explicitly set `host` and `port` rather than relying on defaults if you need different behavior.

**Verification:** Code defaults match documented behavior at:
- `crates/synvoid-config/src/app_server.rs:49-50` - `port = Some(8000)`, `host = Some("127.0.0.1")`

### ConfigManager Pattern

```rust
pub struct ConfigManager {
    pub main: MainConfig,                    // synvoid.toml
    pub sites: HashMap<String, SiteConfig>,  // sites/*.toml
    pub sites_dir: PathBuf,
    pub config_dir: PathBuf,
    site_filenames: HashMap<String, PathBuf>,  // Internal: maps site_id -> config file path for hot-reload
}
```

- `site_filenames`: Private HashMap tracking site IDs to their source file paths. Used internally by `reload_site()` and `reload_all()` to determine which file to re-read when hot-reloading.
- `load_main()` - loads server-wide configuration
- `load_site()` - loads a single domain config
- `discover_sites()` - auto-discovers all `*.toml` in `sites/` directory, returns `Vec<(String, Result<SiteConfig, String>)>` with site ID and result
- `reload_site()` / `reload_all()` - hot-reload support (uses `site_filenames` to find source files)
- `get_site()` - domain-based lookup

### ConfigManager Load Sequence

The ConfigManager loads configuration in this order:

1. **`new()`** - Creates empty manager with default main config, empty sites HashMap, sets up `sites/` and `config/` directories (does NOT load any files)

2. **`load_main(path)`** - Loads the main `synvoid.toml` file, applies token resolution, mesh key loading, and calls `validate()`

3. **`discover_sites()`** - Auto-discovers all `*.toml` files in the `sites/` directory:
   - Creates `sites/` directory if missing
   - Reads each `.toml` file
   - Populates both `sites` HashMap AND `site_filenames` HashMap
   - Returns results with site ID and success/failure

4. **`load_site(path)`** - Manually loads a single site config (also updates `site_filenames`)

5. **`reload_site(domain)`** - Hot-reloads a single site's config by looking up the path in `site_filenames`

6. **`reload_all()`** - Hot-reloads all sites by iterating `sites` HashMap keys

---

## 2. synvoid-utils Crate (`crates/synvoid-utils/`)

### Overview

A minimal utility library providing buffer pooling and serialization abstractions. Feature-gated with `buffer` feature (currently buffer module is always built).

### Buffer Pool Architecture

The buffer pool uses a **tiered arena** design with **sharded storage** and **thread-local caching** for high-performance allocation.

#### Tier Sizes

| Tier | Buffer Size | Pool Capacity | Purpose |
|------|-------------|----------------|---------|
| Small | 4 KB | 512 | HTTP headers, small requests |
| Medium | 64 KB | 256 | Typical request bodies |
| Large | 256 KB | 64 | Large uploads, responses |
| Jumbo | variable | 32 | Above 256 KB allocations |

#### Architecture Components

```
BufferPool
├── shards: Vec<Shard>           (8 shards)
│   └── Shard
│       ├── small: TierArena    (per-shard capacity = 512/8 = 64)
│       ├── medium: TierArena    (per-shard capacity = 256/8 = 32)
│       ├── large: TierArena     (per-shard capacity = 64/8 = 8)
│       └── jumbo: TierArena     (per-shard capacity = 32/8 = 4)
├── TLS_CACHE (thread-local)     (16 buffers per tier per thread)
└── GLOBAL_POOL (lazy static)    (fallback allocation)
```

#### Allocation Flow

1. **Thread-Local Cache First**: Check `TLS_CACHE` for immediate reuse (lock-free pop)
2. **Shard Arena Fallback**: If TLS cache misses, hash thread ID to select shard, pop from arena
3. **Global Pool Fallback**: If all pools empty, allocate fresh `BytesMut`
4. **Memory Limit**: `try_acquire()` checks `GLOBAL_MEMORY_LIMIT` before allocation

#### PooledBuf RAII Wrapper

```rust
pub struct PooledBuf {
    buf: Option<BytesMut>,
    tier: BufferTier,
    requested_size: usize,
    allocated_size: usize,
}
```

- Implements `Deref`/`DerefMut` to `[u8]` for ergonomic usage
- Implements `Drop` to return buffer to appropriate tier cache
- On drop: returns to TLS cache if not full, otherwise to shard arena

#### Key Metrics

- `PoolStats::reuse_rate()` - ratio of buffer reuse to total acquisitions
- `GLOBAL_ALLOCATED_BYTES` - tracks total pooled memory
- `GLOBAL_MEMORY_LIMIT` - optional global cap on pooled memory

#### Thread-Sharding Benefits

- Reduces lock contention (each shard has independent `Mutex<Vec<BytesMut>>`)
- Thread ID hash ensures even distribution across shards
- TLS cache minimizes cross-thread synchronization for hot paths

### Serialization Module

Provides abstraction over serialization with **postcard** as the primary backend:

| Function | Purpose |
|----------|---------|
| `serialize()` | postcard to `Vec<u8>` |
| `deserialize()` | postcard from `&[u8]` |
| `deserialize_rkyv()` | Zero-copy rkyv access (requires `rkyv` feature) |
| `serialize_bincode()` / `deserialize_bincode()` | Legacy compatibility wrappers |
| `serialized_size()` | Get serialized byte length |

**Why Postcard over bincode?**
- Actively maintained
- 30% smaller serialized output
- `no_std` compatible
- Better for embedded/mesh use cases
- **Canonical codebase standard:** Postcard is the preferred serialization format throughout SynVoid for distributed state (DHT, Mesh, persistence), binary signatures, and any network communication.

---

## Key Architectural Patterns

1. **Optional Fields Pattern**: Site config uses `Option<T>` for all optional fields, resolved to concrete types at runtime with defaults via a `*_config()` method.

2. **Config Propagation Pattern**: When adding new fields to `SiteAppServerConfig`, ensure propagation to `AppServerConfig` via `SiteConfig::app_server_config()` at `site/mod.rs:208-261`. Each field in `SiteAppServerConfig` (all `Option<T>`) must have a corresponding resolved field in `AppServerConfig` (with concrete defaults). Example pattern:
   ```rust
   // SiteAppServerConfig: Optional field
   pub require_hashes: Option<bool>,
   // SiteConfig::app_server_config(): Resolved propagation
   require_hashes: site_config.require_hashes.unwrap_or(false),
   ```

2. **Feature-Gated Compilation**: Large subsystems (DNS, Mesh) compile only when features enabled, but core HTTP server always compiles.

3. **Feature Interaction (DNS + mesh configs):**
   - DNS and mesh features can be enabled independently or together
   - When both `dns` and `mesh` features are enabled:
     - `DnsConfig.mesh` can reference mesh nodes for DNS zone transfers
     - Mesh peers can act as recursive resolvers for the DNS server
   - DNS validation only runs if `dns.enabled=true` AND `dns` feature compiled
   - Mesh validation only checks feature flag; `mesh.is_none()` is valid even with mesh config present

4. **Tiered Buffer Pool**: Multi-level caching (TLS → Shard Arena → Fresh Allocation) with memory limits.

### Validation Sequence (MainConfig::validate())

The `MainConfig::validate()` at `crates/synvoid-config/src/main_config.rs:181-214` calls validators in this specific order:

1. **`server.validate()`** - Server bind address, trusted proxies
2. **`http.validate()`** - HTTP protocol limits
3. **`tls.validate()`** - TLS certificates, ACME config
4. **`threat_level.validate()`** - Threat level thresholds
5. **`fallback.validate()`** - Fallback mode configuration
6. **`logging.validate()`** - Log exporter settings
7. **`admin.validate()`** - Admin API configuration (token, CORS, rate limits)
8. **`defaults.validate()`** - Default behaviors (rate limits, bot, honeypot)
9. **`tunnel.validate()`** - Tunnel configuration (WireGuard, QUIC)
10. **`dns.validate()`** - DNS server config (if `dns` feature enabled and `dns.enabled=true`)
11. **Feature gate check** - Fails if `mesh.is_some()` but `mesh` feature not compiled

**Note:** DNS validation only runs if both the `dns` feature is enabled AND `dns.enabled=true`. Mesh configuration fails validation if the `mesh` feature is not compiled (even if `mesh=None`).

### Hot Reload Examples

```toml
# config/sites/example.com.toml
[site]
domains = ["example.com"]
upstream.default = "http://127.0.0.1:8000"
```

**Via CLI:**
```bash
synvoid reload --site example.com    # Reload single site
synvoid reload --all                  # Reload all sites
```

**Via Admin API:**
```bash
# Reload single site
curl -X POST -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/sites/example.com/reload

# Reload all sites
curl -X POST -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8081/api/sites/reload-all
```

**Hot reload behavior:**
- `reload_site()` looks up the source file path via `site_filenames` HashMap
- File is re-parsed and validated
- Only the specified site's config is replaced
- Other sites remain unaffected
- `reload_all()` iterates all known sites and reloads each

4. **Hot Reload**: ConfigManager supports `reload_site()` / `reload_all()` for configuration changes without restart.

5. **Tiered Buffer Pool**: Multi-level caching (TLS → Shard Arena → Fresh Allocation) with memory limits.

6. **Sharded Concurrency**: Buffer pool uses 8 shards to reduce lock contention across threads.

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [Platform & Process Deep Dive](platform_deep_dive.md) - IPC and process management
- [Networking Deep Dive](networking_deep_dive.md) - Buffer usage in networking