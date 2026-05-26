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
| `site/app_server.rs` | Granian Python ASGI/RSGI/WSGI server site config |
| `app_server.rs` | Resolved AppServerConfig for worker processes |
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
│   ├── overseer: OverseerConfig      # Legacy (reserved for future removal; Supervisor uses upgrade config instead)
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
├── site_id: String                    # Derived from site.domains.first() (used as HashMap key in ConfigManager)
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

### ConfigManager Pattern

```rust
pub struct ConfigManager {
    pub main: MainConfig,                    // synvoid.toml
    pub sites: HashMap<String, SiteConfig>,  // sites/*.toml
    pub sites_dir: PathBuf,
    pub config_dir: PathBuf,
}
```

- `load_main()` - loads server-wide configuration
- `load_site()` - loads a single domain config
- `discover_sites()` - auto-discovers all `*.toml` in `sites/` directory, returns `Vec<(String, Result<SiteConfig, String>)>` with site ID and result
- `reload_site()` / `reload_all()` - hot-reload support
- `get_site()` - domain-based lookup

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

3. **Validator Pattern**: Each config has a `validate()` method returning `Result<(), ConfigValidationError>`.

4. **Hot Reload**: ConfigManager supports `reload_site()` / `reload_all()` for configuration changes without restart.

5. **Tiered Buffer Pool**: Multi-level caching (TLS → Shard Arena → Fresh Allocation) with memory limits.

6. **Sharded Concurrency**: Buffer pool uses 8 shards to reduce lock contention across threads.

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [Platform & Process Deep Dive](platform_deep_dive.md) - IPC and process management
- [Networking Deep Dive](networking_deep_dive.md) - Buffer usage in networking