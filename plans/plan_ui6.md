# MaluWAF Admin Panel Enhancement Plan (UI6)

## Executive Summary

This plan outlines the implementation of a comprehensive admin panel enhancement to achieve **100% configuration accessibility** while adding enterprise-grade features: config versioning, dry-run validation, and audit logging. The overseer/master/worker architecture will be maintained throughout.

**Current State:** ~40% configuration coverage (50+ endpoints)
**Target State:** 100% configuration coverage with enterprise features

---

## Phase 1: Foundation & Infrastructure

### 1.1 Config Versioning System

**New Files:**
- `src/admin/config/versioning.rs` - Version storage and retrieval
- `src/admin/config/snapshot.rs` - Config snapshot serialization

**Endpoints:**
```
GET    /api/config/versions              - List config versions
GET    /api/config/versions/{id}         - Get specific version
POST   /api/config/versions/{id}/restore - Restore version
DELETE /api/config/versions/{id}         - Delete version
```

**Implementation Details:**
- Store versions in `{data_dir}/config-versions/` as compressed JSON
- File naming: `{timestamp}-{hash}.json.zst`
- Keep last 50 versions by default (configurable)
- Include metadata: timestamp, user, change summary, config hash
- Use zstd compression for version storage

**Data Structures:**
```rust
pub struct ConfigVersion {
    pub id: String,              // timestamp-hash
    pub timestamp: DateTime<Utc>,
    pub user: String,            // from auth token
    pub description: String,     // change summary
    pub config_hash: String,     // SHA256 of config
    pub section: Option<String>, // which section changed
    pub snapshot: String,        // compressed JSON
}

pub struct VersionListResponse {
    pub versions: Vec<ConfigVersionSummary>,
    pub total: usize,
    pub retention_days: u32,
}

pub struct RestoreRequest {
    pub description: Option<String>, // override restore reason
}
```

### 1.2 Config Validation Framework

**New Files:**
- `src/admin/config/validation.rs` - Validation engine
- `src/admin/config/diff.rs` - Config diff computation

**Endpoints:**
```
POST /api/config/validate       - Validate config without saving
POST /api/config/preview        - Preview changes (diff + validation)
POST /api/config/section/{name}/validate - Validate single section
```

**Validation Types:**
1. **Schema Validation** - Type checking, required fields
2. **Semantic Validation** - Logical constraints (e.g., cert/key pairing)
3. **File Validation** - Certificate files exist, permissions correct
4. **Network Validation** - Ports available, IPs valid
5. **Dependency Validation** - Required features enabled

**Response Format:**
```rust
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

pub struct ValidationError {
    pub path: String,           // JSON pointer to field
    pub message: String,        // human-readable error
    pub code: String,           // error code for i18n
    pub severity: ErrorSeverity,
}

pub struct ConfigDiff {
    pub section: String,
    pub field: String,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub change_type: ChangeType, // Added, Modified, Removed
}
```

### 1.3 Audit Logging

**New Files:**
- `src/admin/config/audit.rs` - Audit log service
- `src/admin/config/audit_types.rs` - Audit data structures

**Endpoints:**
```
GET /api/config/audit-log              - List audit entries
GET /api/config/audit-log/{id}         - Get specific entry
GET /api/config/audit-log/stats        - Audit statistics
```

**Audit Log Entry:**
```rust
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub action: AuditAction,
    pub section: String,
    pub config_hash_before: String,
    pub config_hash_after: String,
    pub diff: Vec<ConfigDiff>,
    pub result: AuditResult,
    pub metadata: AuditMetadata,
}

pub enum AuditAction {
    Create,
    Update,
    Delete,
    Restore,
    Validate,
    Export,
    Import,
}

pub enum AuditResult {
    Success,
    Failed { reason: String },
    Partial { applied: Vec<String>, failed: Vec<String> },
}
```

**Storage:**
- JSONL format in `{data_dir}/audit/audit-{date}.log`
- Auto-rotation: daily files, compress after 7 days, delete after 90 days
- Index by timestamp for efficient queries

### 1.4 Fix Worker Restart

**File:** `src/master/system.rs:205-207`

**Current State:**
```rust
async fn restart_worker(...) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "Not implemented")
}
```

**Implementation:**
```rust
async fn restart_worker(
    State(state): State<AdminState>,
    Path(worker_id): Path<u32>,
) -> Result<Json<RestartResponse>, AdminError> {
    // 1. Validate worker exists
    let worker = state.process.get_worker(worker_id)
        .ok_or(AdminError::WorkerNotFound(worker_id))?;

    // 2. Send restart command via IPC
    let op_id = uuid::Uuid::new_v4().to_string();
    state.process.restart_worker(worker_id, op_id.clone()).await?;

    // 3. Return operation ID for polling
    Ok(Json(RestartResponse {
        operation_id: op_id,
        status: "pending",
        worker_id,
    }))
}

async fn restart_worker_status(
    State(state): State<AdminState>,
    Path((worker_id, op_id)): Path<(u32, String)>,
) -> Result<Json<RestartStatus>, AdminError> {
    // Poll restart operation status
}
```

**New IPC Message (src/process/ipc.rs):**
```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message {
    // ... existing variants
    RestartWorkerRequest {
        worker_id: u32,
        operation_id: String,
        graceful: bool,
        timeout_secs: u64,
    },
    RestartWorkerResponse {
        worker_id: u32,
        operation_id: String,
        success: bool,
        error: Option<String>,
    },
}
```

---

## Phase 2: Critical Security Configs

### 2.1 TLS Configuration

**File:** `src/admin/handlers/tls.rs` (new)

**Endpoints:**
```
GET  /api/config/tls    - Get TLS configuration
PUT  /api/config/tls    - Update TLS configuration
POST /api/config/tls/cert/validate - Validate certificate
```

**Configuration Fields:**
```rust
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub tls_1_3_only: bool,
    pub client_auth: ClientAuthConfig,
    pub acme: Option<AcmeConfig>,
    pub cipher_suites: Vec<String>,
    pub alpn_protocols: Vec<String>,
}

pub struct ClientAuthConfig {
    pub enabled: bool,
    pub ca_path: Option<String>,
    pub verification: ClientCertVerification,
}

pub struct AcmeConfig {
    pub enabled: bool,
    pub domain: String,
    pub email: String,
    pub directory_url: String,
    pub renewal_days: u32,
}
```

**Validation Rules:**
- cert_path and key_path must exist
- Certificate must be valid and not expired
- Key must match certificate
- CA file must exist if client auth enabled
- ACME domain must be valid hostname

### 2.2 HTTP Configuration

**File:** `src/admin/handlers/http_config.rs` (new)

**Endpoints:**
```
GET  /api/config/http - Get HTTP configuration
PUT  /api/config/http - Update HTTP configuration
```

**Configuration Fields:**
```rust
pub struct HttpConfig {
    pub header_read_timeout_secs: u64,      // 1-300, default 30
    pub keep_alive_timeout_secs: u64,       // 1-600, default 75
    pub max_headers: usize,                 // 1-10000, default 100
    pub max_request_size: usize,            // 1KB-100MB, default 10MB
    pub max_concurrent_requests: usize,     // 1-100000, default 10000
    pub enable_h2c: bool,                   // HTTP/2 cleartext
    pub enable_h3: bool,                    // HTTP/3
    pub request_body_timeout_secs: u64,     // 1-300, default 60
    pub idle_timeout_secs: u64,             // 1-3600, default 90
}
```

**Validation Rules:**
- All timeouts within reasonable bounds
- max_request_size < max_memory per worker
- HTTP/3 requires quiche or h3 feature

### 2.3 Security Configuration

**File:** `src/admin/handlers/security_config.rs` (new)

**Endpoints:**
```
GET  /api/config/security       - Get security configuration
PUT  /api/config/security       - Update security configuration
GET  /api/config/security/ipc   - Get IPC security settings
PUT  /api/config/security/ipc   - Update IPC security settings
```

**Configuration Fields:**
```rust
pub struct SecurityConfig {
    pub ipc: IpcSecurityConfig,
    pub headers: SecurityHeadersConfig,
    pub cors: CorsSecurityConfig,
    pub csrf: CsrfConfig,
    pub rate_limit: ApiRateLimitConfig,
}

pub struct IpcSecurityConfig {
    pub require_auth: bool,
    pub session_key_rotation_hours: u32,
    pub socket_permissions: u32,  // octal, e.g., 0o600
    pub max_message_size: usize,
    pub connection_timeout_secs: u64,
}

pub struct SecurityHeadersConfig {
    pub hsts_max_age: u64,        // 0 to disable
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
    pub x_content_type_options: bool,
    pub x_frame_options: XFrameOption,
    pub content_security_policy: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
}

pub enum XFrameOption {
    Deny,
    SameOrigin,
    AllowFrom(String),
}

pub struct CsrfConfig {
    pub enabled: bool,
    pub cookie_name: String,
    pub header_name: String,
    pub token_length: usize,
    pub token_ttl_secs: u64,
}
```

### 2.4 Admin Security Configuration

**File:** `src/config/admin.rs` (extend existing)

**New Endpoints:**
```
GET  /api/config/admin-security - Get admin API security settings
PUT  /api/config/admin-security - Update admin API security settings
```

**Configuration Fields:**
```rust
pub struct AdminSecurityConfig {
    pub token_ttl_secs: u64,           // 300-86400, default 3600
    pub require_https: bool,           // force HTTPS for admin API
    pub allowed_ips: Vec<IpNetwork>,   // IP whitelist
    pub max_login_attempts: u32,       // 1-100, default 10
    pub lockout_duration_secs: u64,    // 60-3600, default 300
    pub session_idle_timeout: u64,     // 60-3600, default 900
    pub secure_cookies: bool,          // Secure flag on cookies
    pub same_site: SameSitePolicy,     // Strict/Lax/None
}

pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
}
```

---

## Phase 3: Performance Configs

### 3.1 Rate Limiting Tuning

**File:** `src/admin/handlers/rate_limit_config.rs` (new)

**Endpoints:**
```
GET  /api/config/rate-limits        - Get rate limit configuration
PUT  /api/config/rate-limits        - Update rate limit configuration
GET  /api/config/rate-limits/sites  - Per-site rate limits
PUT  /api/config/rate-limits/sites/{site} - Update site rate limits
```

**Configuration Fields:**
```rust
pub struct RateLimitConfig {
    pub global: GlobalRateLimit,
    pub per_site: Vec<SiteRateLimit>,
    pub memory: RateLimitMemoryConfig,
    pub storage: RateLimitStorageConfig,
}

pub struct GlobalRateLimit {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub window_secs: u64,
    pub whitelist: Vec<IpNetwork>,
}

pub struct SiteRateLimit {
    pub site: String,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub paths: Vec<PathRateLimit>,
}

pub struct PathRateLimit {
    pub pattern: String,  // glob pattern
    pub requests_per_second: u32,
    pub burst_size: u32,
}

pub struct RateLimitMemoryConfig {
    pub max_entries: usize,        // 1000-10000000
    pub cleanup_interval_secs: u64,
    pub entry_ttl_secs: u64,
}
```

**Validation Rules:**
- requests_per_second > 0
- burst_size >= requests_per_second
- max_entries reasonable for available memory
- Patterns must be valid globs

### 3.2 Bot Detection Configuration

**File:** `src/admin/handlers/bot_config.rs` (new)

**Endpoints:**
```
GET  /api/config/bot-detection       - Get bot detection config
PUT  /api/config/bot-detection       - Update bot detection config
GET  /api/config/bot-detection/rules - List bot rules
POST /api/config/bot-detection/rules - Add bot rule
PUT  /api/config/bot-detection/rules/{id} - Update rule
DELETE /api/config/bot-detection/rules/{id} - Delete rule
```

**Configuration Fields:**
```rust
pub struct BotDetectionConfig {
    pub enabled: bool,
    pub mode: BotDetectionMode,  // Log, Challenge, Block
    pub challenge_type: ChallengeType,  // Captcha, JavaScript
    pub user_agent_rules: Vec<UserAgentRule>,
    pub behavior_rules: Vec<BehaviorRule>,
    pub whitelisted_ips: Vec<IpNetwork>,
    pub whitelisted_user_agents: Vec<String>,
}

pub enum BotDetectionMode {
    Disabled,
    LogOnly,
    Challenge,
    Block,
}

pub enum ChallengeType {
    Captcha,
    JavaScript,
    Honeypot,
}

pub struct UserAgentRule {
    pub id: String,
    pub pattern: String,  // regex
    pub action: BotAction,
    pub severity: u8,     // 1-10
    pub enabled: bool,
}

pub struct BehaviorRule {
    pub id: String,
    pub name: String,
    pub max_requests_per_minute: u32,
    pub max_error_rate: f32,  // 0.0-1.0
    pub max_payload_size: usize,
    pub action: BotAction,
}
```

### 3.3 Traffic Shaping Configuration

**File:** `src/admin/handlers/traffic_config.rs` (new)

**Endpoints:**
```
GET  /api/config/traffic-shaping       - Get traffic shaping config
PUT  /api/config/traffic-shaping       - Update traffic shaping config
GET  /api/config/traffic-shaping/rules - List shaping rules
POST /api/config/traffic-shaping/rules - Add shaping rule
```

**Configuration Fields:**
```rust
pub struct TrafficShapingConfig {
    pub enabled: bool,
    pub bandwidth_limits: BandwidthLimits,
    pub priority_rules: Vec<PriorityRule>,
    pub qos: QosConfig,
}

pub struct BandwidthLimits {
    pub global_mbps: Option<u64>,
    pub per_site_mbps: Vec<SiteBandwidthLimit>,
    pub per_ip_mbps: Option<u64>,
}

pub struct SiteBandwidthLimit {
    pub site: String,
    pub upload_mbps: Option<u64>,
    pub download_mbps: Option<u64>,
}

pub struct PriorityRule {
    pub id: String,
    pub name: String,
    pub priority: u8,  // 0=highest, 7=lowest
    pub matchers: Vec<RequestMatcher>,
}

pub struct QosConfig {
    pub enabled: bool,
    pub queue_depth: usize,
    pub scheduling: SchedulingPolicy,
}

pub enum SchedulingPolicy {
    Fifo,
    Lifo,
    WeightedFair,
    Priority,
}
```

### 3.4 Process Manager Enhancement

**File:** Extend `src/admin/handlers/config.rs`

**Enhanced Endpoint:**
```
PUT /api/config/process-manager - Now includes additional fields
```

**New Fields:**
```rust
pub struct ProcessManagerConfig {
    // Existing fields
    pub min_workers: usize,
    pub max_workers: usize,
    pub restart_cooldown_secs: u64,
    pub heartbeat_timeout_secs: u64,

    // New fields
    pub worker_affinity: Vec<CpuSet>,       // CPU affinity per worker
    pub resource_limits: ResourceLimits,
    pub memory_limit_mb: Option<usize>,
    pub oom_score_adj: Option<i32>,
    pub nice_level: Option<i8>,
}

pub struct ResourceLimits {
    pub max_fds: Option<u64>,
    pub max_memory_mb: Option<usize>,
    pub max_cpu_percent: Option<f32>,
    pub max_file_size_mb: Option<usize>,
}
```

---

## Phase 4: Feature Configs

### 4.1 DNS Server Configuration (feature-gated)

**Feature Gate:** `#[cfg(feature = "dns")]`

**File:** `src/admin/handlers/dns_config.rs` (new)

**Endpoints:**
```
GET  /api/config/dns                - Get DNS server config
PUT  /api/config/dns                - Update DNS server config
GET  /api/config/dns/zones          - List DNS zones
POST /api/config/dns/zones          - Add DNS zone
GET  /api/config/dns/zones/{name}   - Get zone details
PUT  /api/config/dns/zones/{name}   - Update zone
DELETE /api/config/dns/zones/{name} - Delete zone
GET  /api/config/dns/dnssec         - Get DNSSEC config
PUT  /api/config/dns/dnssec         - Update DNSSEC config
```

**Configuration Fields:**
```rust
pub struct DnsAdminConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub mode: DnsMode,  // Authoritative, Forwarder, Recursive
    pub ratelimit: DnsRateLimit,
    pub dnssec: DnsSecConfig,
    pub zones: Vec<ZoneConfig>,
    pub forwarders: Vec<ForwarderConfig>,
    pub cache: DnsCacheConfig,
}

pub enum DnsMode {
    Authoritative,
    Forwarder,
    Recursive,
    Combined,
}

pub struct DnsSecConfig {
    pub enabled: bool,
    pub validation: DnsSecValidation,
    pub signing: Option<DnsSecSigning>,
    pub trust_anchors: Vec<TrustAnchorConfig>,
}

pub struct ZoneConfig {
    pub name: String,
    pub zone_type: ZoneType,
    pub file: Option<String>,
    pub records: Vec<DnsRecord>,
    pub dnssec_enabled: bool,
}
```

### 4.2 Tunnel Configuration

**File:** `src/admin/handlers/tunnel_config.rs` (new)

**Endpoints:**
```
GET  /api/config/tunnel         - Get tunnel configuration
PUT  /api/config/tunnel         - Update tunnel configuration
GET  /api/config/tunnel/status  - Get tunnel status
POST /api/config/tunnel/connect - Initiate tunnel connection
POST /api/config/tunnel/disconnect - Disconnect tunnel
```

**Configuration Fields:**
```rust
pub struct TunnelConfig {
    pub enabled: bool,
    pub mode: TunnelMode,
    pub vpn: Option<VpnConfig>,
    pub quic: Option<QuicConfig>,
    pub mesh_tunnel: Option<MeshTunnelConfig>,
}

pub enum TunnelMode {
    Vpn,
    Quic,
    Mesh,
    Hybrid,
}

pub struct VpnConfig {
    pub provider: VpnProvider,
    pub server: String,
    pub port: u16,
    pub protocol: VpnProtocol,
    pub credentials: Option<VpnCredentialsRef>,
    pub kill_switch: bool,
    pub auto_reconnect: bool,
}

pub struct QuicConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub max_idle_timeout_ms: u64,
    pub max_payload_size: usize,
    pub alpn_protocols: Vec<String>,
    pub certificate_verification: bool,
}

pub struct MeshTunnelConfig {
    pub enabled: bool,
    pub mesh_id: String,
    pub nodes: Vec<MeshNodeConfig>,
    pub encryption: TunnelEncryption,
}
```

### 4.3 Mesh Network Enhancement

**File:** Extend `src/admin/handlers/mesh_admin.rs`

**New Endpoints:**
```
GET  /api/config/mesh           - Get mesh network config
PUT  /api/config/mesh           - Update mesh network config
GET  /api/config/mesh/nodes     - List mesh node configs
POST /api/config/mesh/nodes     - Add mesh node
PUT  /api/config/mesh/nodes/{id} - Update node config
DELETE /api/config/mesh/nodes/{id} - Remove node
```

**Configuration Fields:**
```rust
pub struct MeshConfig {
    pub enabled: bool,
    pub node_id: String,
    pub bind_address: String,
    pub port: u16,
    pub discovery: MeshDiscovery,
    pub encryption: MeshEncryption,
    pub routing: MeshRouting,
    pub heartbeat_secs: u64,
    pub node_timeout_secs: u64,
}

pub struct MeshDiscovery {
    pub mode: DiscoveryMode,  // Static, Multicast, DHT
    pub multicast_addr: Option<SocketAddr>,
    pub bootstrap_nodes: Vec<SocketAddr>,
}

pub enum MeshEncryption {
    None,
    Tls(TlsConfig),
    NoiseProtocol(NoiseConfig),
}

pub struct MeshRouting {
    pub algorithm: RoutingAlgorithm,
    pub max_hops: u8,
    pub route_cache_ttl_secs: u64,
}
```

### 4.4 Plugin Management

**File:** `src/admin/handlers/plugin_config.rs` (new)

**Endpoints:**
```
GET  /api/config/plugins            - Get plugin configuration
PUT  /api/config/plugins            - Update plugin configuration
GET  /api/plugins                   - List installed plugins
POST /api/plugins                   - Install plugin (upload WASM)
GET  /api/plugins/{id}              - Get plugin details
PUT  /api/plugins/{id}              - Update plugin config
DELETE /api/plugins/{id}            - Uninstall plugin
POST /api/plugins/{id}/enable       - Enable plugin
POST /api/plugins/{id}/disable      - Disable plugin
GET  /api/plugins/{id}/logs         - Get plugin logs
POST /api/plugins/{id}/metrics      - Get plugin metrics
```

**Configuration Fields:**
```rust
pub struct PluginConfig {
    pub enabled: bool,
    pub plugins_dir: String,
    pub max_memory_mb: usize,
    pub max_execution_time_ms: u64,
    pub allow_network: bool,
    pub allow_filesystem: bool,
    pub allowed_paths: Vec<String>,
    pub plugins: Vec<PluginEntry>,
}

pub struct PluginEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub priority: i32,
    pub hooks: Vec<HookType>,
}

pub enum HookType {
    OnRequest,
    OnResponse,
    OnHeaders,
    OnBody,
    OnError,
    OnStartup,
    OnShutdown,
}
```

---

## Phase 5: UI/UX Improvements

### 5.1 Config Editor UI Pages

**New Pages (admin-ui/src/pages/):**

1. **SecuritySettings.tsx** - TLS, HTTP, Security headers
2. **PerformanceSettings.tsx** - Rate limits, Bot detection, Traffic shaping
3. **NetworkSettings.tsx** - DNS, Tunnels, Mesh
4. **PluginManager.tsx** - Plugin list, installation, configuration
5. **ConfigVersions.tsx** - Version history browser
6. **AuditLog.tsx** - Audit log viewer with filters

**Components (admin-ui/src/components/config/):**

1. **ConfigEditor.tsx** - Generic config editor with validation
2. **ConfigSection.tsx** - Collapsible section with status indicators
3. **ConfigDiff.tsx** - Visual diff display
4. **ValidationErrors.tsx** - Error display with field linking
5. **DryRunPreview.tsx** - Change preview modal
6. **VersionHistory.tsx** - Timeline view of versions
7. **RestoreConfirm.tsx** - Restore confirmation dialog

### 5.2 Dashboard Enhancements

**New Widgets:**

1. **Config Status Widget** - Shows config health, last change
2. **Quick Actions** - Buttons for common operations
3. **Validation Status** - Real-time validation feedback
4. **Change Notifications** - Toast notifications for config changes
5. **System Health** - Aggregated health from all subsystems

### 5.3 API Documentation Updates

**File:** `src/admin/openapi.rs`

**Updates:**
- Add all new endpoints to OpenAPI spec
- Include request/response schemas
- Add validation rules as OpenAPI constraints
- Generate examples for each endpoint
- Add authentication requirements

---

## Phase 6: Testing & Hardening

### 6.1 Integration Tests

**File:** `tests/admin_test.rs` (new)

**Test Categories:**

```rust
#[cfg(test)]
mod config_versioning_tests {
    #[test]
    fn test_create_version() { ... }
    #[test]
    fn test_list_versions() { ... }
    #[test]
    fn test_restore_version() { ... }
    #[test]
    fn test_version_retention() { ... }
}

#[cfg(test)]
mod config_validation_tests {
    #[test]
    fn test_valid_config_passes() { ... }
    #[test]
    fn test_invalid_tls_config() { ... }
    #[test]
    fn test_invalid_port_range() { ... }
    #[test]
    fn test_missing_certificate_file() { ... }
}

#[cfg(test)]
mod config_audit_tests {
    #[test]
    fn test_audit_log_created() { ... }
    #[test]
    fn test_audit_log_query() { ... }
    #[test]
    fn test_audit_log_rotation() { ... }
}

#[cfg(test)]
mod worker_restart_tests {
    #[test]
    fn test_restart_worker() { ... }
    #[test]
    fn test_restart_nonexistent_worker() { ... }
    #[test]
    fn test_restart_worker_timeout() { ... }
}
```

### 6.2 Security Tests

**Tests:**
- Auth bypass attempts on config endpoints
- Config injection via JSON payloads
- Path traversal in file path fields
- CSRF token validation
- Rate limiting enforcement on sensitive endpoints
- Token expiration handling

### 6.3 Performance Tests

**Benchmarks:**
- Config read/write latency
- Version storage scaling (100, 1000, 10000 versions)
- Concurrent config update handling
- Audit log query performance
- Validation performance for large configs

---

## File Structure Summary

### New Files to Create

```
src/admin/
├── config/
│   ├── mod.rs                    # Module declarations
│   ├── versioning.rs             # Version management
│   ├── snapshot.rs               # Config snapshots
│   ├── validation.rs             # Validation engine
│   ├── diff.rs                   # Diff computation
│   ├── audit.rs                  # Audit logging
│   └── audit_types.rs            # Audit data structures
└── handlers/
    ├── tls.rs                    # TLS config handler
    ├── http_config.rs            # HTTP config handler
    ├── security_config.rs        # Security config handler
    ├── rate_limit_config.rs      # Rate limit config handler
    ├── bot_config.rs             # Bot detection handler
    ├── traffic_config.rs         # Traffic shaping handler
    ├── dns_config.rs             # DNS config handler (feature-gated)
    ├── tunnel_config.rs          # Tunnel config handler
    └── plugin_config.rs          # Plugin config handler

src/config/
└── (extend existing files)

src/process/
└── ipc.rs                        # New IPC messages for worker restart

tests/
└── admin_test.rs                 # Admin panel tests

admin-ui/src/
├── pages/
│   ├── SecuritySettings.tsx
│   ├── PerformanceSettings.tsx
│   ├── NetworkSettings.tsx
│   ├── PluginManager.tsx
│   ├── ConfigVersions.tsx
│   └── AuditLog.tsx
└── components/config/
    ├── ConfigEditor.tsx
    ├── ConfigSection.tsx
    ├── ConfigDiff.tsx
    ├── ValidationErrors.tsx
    ├── DryRunPreview.tsx
    ├── VersionHistory.tsx
    └── RestoreConfirm.tsx
```

### Files to Modify

```
src/admin/
├── mod.rs                        # Register new routes
├── state.rs                      # Add new service states
├── handlers/
│   ├── mod.rs                    # Module declarations
│   ├── config.rs                 # Enhanced config endpoints
│   └── system.rs                 # Fix worker restart
└── openapi.rs                    # Update API documentation

src/config/
├── main.rs                       # Ensure all config types exported
├── admin.rs                      # Extended admin security config
└── process.rs                    # Process manager enhancements

src/master/
└── system.rs                     # Worker restart implementation
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Overseer                                        │
│  - OverseerConfig accessible via /api/config/overseer                    │
│  - No changes to overseer implementation                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            Master                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                        Admin API                                 │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │    │
│  │  │ Config       │ │ Versioning   │ │ Audit        │            │    │
│  │  │ Handlers     │ │ Service      │ │ Logger       │            │    │
│  │  │ (20+ new)    │ │              │ │              │            │    │
│  │  └──────────────┘ └──────────────┘ └──────────────┘            │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │    │
│  │  │ Validation   │ │ Diff         │ │ Process      │            │    │
│  │  │ Engine       │ │ Calculator   │ │ Manager+     │            │    │
│  │  └──────────────┘ └──────────────┘ └──────────────┘            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Config Storage Layer                           │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │    │
│  │  │ Config       │ │ Version      │ │ Audit        │            │    │
│  │  │ Files        │ │ Snapshots    │ │ Logs         │            │    │
│  │  │ (*.json)     │ │ (*.json.zst) │ │ (*.log)      │            │    │
│  │  └──────────────┘ └──────────────┘ └──────────────┘            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │ IPC (Unix domain sockets)
                                    │ (enhanced with RestartWorker)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Workers                                         │
│  - Receive config updates via existing IPC                               │
│  - No changes to worker implementation                                   │
│  - Respond to restart commands via IPC                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Dependency Graph

```
Phase 1 (Foundation)
    │
    ├── 1.1 Config Versioning ──────┐
    ├── 1.2 Validation Framework ───┤
    ├── 1.3 Audit Logging ──────────┤
    └── 1.4 Worker Restart ─────────┘
            │
            ▼
Phase 2 (Security) ──────── Phase 3 (Performance)
    │                               │
    ├── 2.1 TLS                    ├── 3.1 Rate Limits
    ├── 2.2 HTTP                   ├── 3.2 Bot Detection
    ├── 2.3 Security               ├── 3.3 Traffic Shaping
    └── 2.4 Admin Security         └── 3.4 Process Manager
            │                               │
            └───────────┬───────────────────┘
                        │
                        ▼
                Phase 4 (Features)
                        │
                        ├── 4.1 DNS (feature-gated)
                        ├── 4.2 Tunnel
                        ├── 4.3 Mesh Enhancement
                        └── 4.4 Plugins
                        │
                        ▼
                Phase 5 (UI/UX)
                        │
                        ├── 5.1 Config Editor Pages
                        ├── 5.2 Dashboard Enhancements
                        └── 5.3 API Documentation
                        │
                        ▼
                Phase 6 (Testing)
                        │
                        ├── 6.1 Integration Tests
                        ├── 6.2 Security Tests
                        └── 6.3 Performance Tests
```

---

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Config version storage grows large | Medium | High | Implement rotation, compression |
| Validation misses edge cases | High | Medium | Comprehensive test suite |
| Worker restart causes downtime | High | Low | Graceful restart with timeout |
| Feature-gated code diverges | Low | Medium | CI tests with all features |
| UI components become stale | Medium | Medium | Regular dependency updates |
| Audit log storage fills disk | High | Medium | Rotation policy, monitoring |

---

## Success Criteria

### Functional Requirements
- [ ] 100% configuration accessible via admin panel
- [ ] Config versioning with restore capability
- [ ] Dry-run validation before applying changes
- [ ] Complete audit trail of all config changes
- [ ] Worker restart endpoint fully functional
- [ ] All security configs editable (TLS, HTTP, Headers)
- [ ] All performance configs editable (Rate limits, Bot, Traffic)
- [ ] All feature configs accessible (DNS, Tunnel, Mesh, Plugins)

### Non-Functional Requirements
- [ ] Config read/write latency < 50ms (p99)
- [ ] Version restore latency < 200ms
- [ ] Audit log query latency < 100ms
- [ ] No memory leaks in long-running processes
- [ ] API documentation 100% complete
- [ ] Test coverage > 80% for new code

### Architecture Requirements
- [ ] Overseer unchanged
- [ ] Worker unchanged (except IPC message handling)
- [ ] Master handles all admin functionality
- [ ] IPC communication maintained
- [ ] Feature gates respected

---

## Appendix C: Error Handling Standards

All new endpoints must follow consistent error handling:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Configuration not found: {0}")]
    NotFound(String),
    
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Version not found: {0}")]
    VersionNotFound(String),
    
    #[error("Cannot restore: {reason}")]
    RestoreFailed { reason: String },
    
    #[error("Storage error: {0}")]
    Storage(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Rate limit exceeded")]
    RateLimited,
}

impl IntoResponse for ConfigError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ConfigError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ConfigError::Validation(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ConfigError::VersionNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ConfigError::RestoreFailed { .. } => (StatusCode::CONFLICT, self.to_string()),
            ConfigError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Storage error".to_string()),
            ConfigError::Serialization(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error".to_string()),
            ConfigError::PermissionDenied => (StatusCode::FORBIDDEN, self.to_string()),
            ConfigError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
        };
        
        (status, Json(json!({ "error": message }))).into_response()
    }
}
```

---

## Appendix D: AdminState Integration

New services to add to `AdminState` in `src/admin/state.rs`:

```rust
pub struct AdminState {
    // Existing
    pub metrics: MetricsState,
    pub waf_tracking: WafTrackingState,
    pub security: SecurityState,
    pub mesh: MeshState,
    pub honeypot: HoneypotState,
    pub process: ProcessState,
    
    // New (Phase 1)
    pub config_versioning: ConfigVersioningService,
    pub config_validation: ConfigValidationService,
    pub audit_logger: AuditLogger,
}

impl AdminState {
    pub fn new(config: &MainConfig, ...) -> Self {
        Self {
            // ... existing initialization
            config_versioning: ConfigVersioningService::new(
                config.data_dir.join("config-versions"),
                config.admin.version_retention.unwrap_or(50),
            ),
            config_validation: ConfigValidationService::new(config),
            audit_logger: AuditLogger::new(
                config.data_dir.join("audit"),
                config.admin.audit_retention_days.unwrap_or(90),
            ),
        }
    }
}
```

---

## Appendix E: Route Registration

New routes to add in `src/admin/mod.rs`:

```rust
fn create_router(state: AdminState) -> Router {
    Router::new()
        // ... existing routes
        
        // Phase 1: Foundation
        .route("/api/config/versions", get(handlers::config::list_versions))
        .route("/api/config/versions/:id", get(handlers::config::get_version))
        .route("/api/config/versions/:id/restore", post(handlers::config::restore_version))
        .route("/api/config/validate", post(handlers::config::validate_config))
        .route("/api/config/preview", post(handlers::config::preview_changes))
        .route("/api/config/audit-log", get(handlers::config::get_audit_log))
        .route("/api/system/workers/:id/restart", post(handlers::system::restart_worker))
        
        // Phase 2: Security
        .route("/api/config/tls", get(handlers::tls::get_tls).put(handlers::tls::update_tls))
        .route("/api/config/tls/cert/validate", post(handlers::tls::validate_cert))
        .route("/api/config/http", get(handlers::http_config::get_http).put(handlers::http_config::update_http))
        .route("/api/config/security", get(handlers::security_config::get_security).put(handlers::security_config::update_security))
        .route("/api/config/admin-security", get(handlers::security_config::get_admin_security).put(handlers::security_config::update_admin_security))
        
        // Phase 3: Performance
        .route("/api/config/rate-limits", get(handlers::rate_limit_config::get_rate_limits).put(handlers::rate_limit_config::update_rate_limits))
        .route("/api/config/bot-detection", get(handlers::bot_config::get_bot_detection).put(handlers::bot_config::update_bot_detection))
        .route("/api/config/traffic-shaping", get(handlers::traffic_config::get_traffic_shaping).put(handlers::traffic_config::update_traffic_shaping))
        
        // Phase 4: Features (some feature-gated)
        #[cfg(feature = "dns")]
        .route("/api/config/dns", get(handlers::dns_config::get_dns).put(handlers::dns_config::update_dns))
        .route("/api/config/tunnel", get(handlers::tunnel_config::get_tunnel).put(handlers::tunnel_config::update_tunnel))
        .route("/api/config/mesh", get(handlers::mesh_admin::get_mesh_config).put(handlers::mesh_admin::update_mesh_config))
        .route("/api/config/plugins", get(handlers::plugin_config::get_plugins).put(handlers::plugin_config::update_plugins))
        
        // ... middleware layers
}
```

---

## Timeline

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1-2 | Phase 1 | Versioning, Validation, Audit, Worker Restart |
| 2-3 | Phase 2 | TLS, HTTP, Security, Admin Security configs |
| 3-4 | Phase 3 | Rate Limits, Bot Detection, Traffic, Process Manager |
| 4-5 | Phase 4 | DNS, Tunnel, Mesh, Plugins configs |
| 5-6 | Phase 5 | UI pages, Dashboard, Documentation |
| 6-7 | Phase 6 | Integration, Security, Performance tests |
| 8 | Buffer | Bug fixes, polish, documentation |

---

## Implementation Notes

1. **Feature Gates**: DNS config handler requires `#[cfg(feature = "dns")]` compilation
2. **Backward Compatibility**: All config changes must be backward compatible
3. **Migration**: No migration needed - new configs have sensible defaults
4. **Rollback**: Config versioning allows instant rollback to any previous state
5. **Security**: All new endpoints require authentication (existing middleware)
6. **Performance**: Version storage uses compression to minimize disk usage
7. **Audit**: All config changes logged by default, cannot be disabled

## Additional Considerations

### Config Import/Export Enhancement

**File:** Extend `src/admin/handlers/config.rs`

Current import/export endpoints exist but need enhancement:

```
POST /api/config/export - Enhanced with format options
POST /api/config/import - Enhanced with validation
```

**Enhancements:**
- Support multiple formats: JSON, YAML, TOML
- Include version metadata in exports
- Dry-run import option
- Selective section export/import

### Legacy Code Cleanup

**File:** `src/admin/legacy.rs` (385 lines)

The legacy HTML dashboard is not integrated into the module tree. Options:
1. **Remove** - Delete if not needed (recommended)
2. **Migrate** - Move useful parts to new UI
3. **Preserve** - Keep for backward compatibility

**Recommendation:** Remove in Phase 1 as dead code, document in migration guide.

### Config Type Reuse

Important: Several config types already exist in `src/config/`:
- `TlsConfig` in `src/config/tls.rs`
- `HttpConfig` in `src/config/http.rs`
- `SecurityConfig` in `src/config/security.rs`

**Implementation approach:** Handler endpoints should return/existing config types directly, not create new duplicates. Add admin-specific wrappers only if needed for API convenience.

### Backward Compatibility Testing

Add tests to verify:
- Old config files parse correctly
- Missing fields get defaults
- New fields don't break old configs
- Feature-gated fields handle missing features gracefully

### Developer Quick Start

For developers implementing this plan:

```bash
# Start with Phase 1.4 (Worker Restart) - smallest change
# Then Phase 1.1 (Versioning) - foundation for everything else
# Use existing config types from src/config/ whenever possible
# Run tests frequently: cargo test --test integration_test
```

---

## Appendix A: Existing Config Structures Reference

| Config Type | Location | Admin Endpoint | Status |
|-------------|----------|----------------|--------|
| `MainConfig` | `src/config/main.rs` | `/api/config/main` | ✅ Exists |
| `ServerConfig` | `src/config/server.rs` | - | ❌ Missing |
| `AdminConfig` | `src/config/admin.rs` | - | ❌ Missing (partial) |
| `TlsConfig` | `src/config/tls.rs` | - | ❌ Missing |
| `HttpConfig` | `src/config/http.rs` | - | ❌ Missing |
| `SecurityConfig` | `src/config/security.rs` | - | ❌ Missing |
| `DnsConfig` | `src/config/dns.rs` | - | ❌ Missing (feature-gated) |
| `TunnelConfig` | `src/config/tunnel.rs` | - | ❌ Missing |
| `MeshConfig` | `src/config/mesh.rs` | Partial | ⚠️ Partial |
| `ProcessManagerConfig` | `src/config/process.rs` | `/api/config/process-manager` | ✅ Exists |
| `ThreatLevelConfig` | `src/config/protection.rs` | Partial | ⚠️ Partial |
| `LoggingConfig` | `src/config/logging.rs` | - | ❌ Missing |
| `PluginConfig` | `src/config/plugins.rs` | - | ❌ Missing |

---

## Appendix B: IPC Message Extensions

New IPC messages needed for admin features:

```rust
// In src/process/ipc.rs

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message {
    // ... existing variants
    
    // Worker restart (Phase 1.4)
    RestartWorkerRequest {
        worker_id: u32,
        operation_id: String,
        graceful: bool,
        timeout_secs: u64,
    },
    RestartWorkerResponse {
        worker_id: u32,
        operation_id: String,
        success: bool,
        error: Option<String>,
    },
    
    // Config hot-reload notification (optional enhancement)
    ConfigReloaded {
        sections: Vec<String>,
        timestamp: DateTime<Utc>,
    },
}
```

---

## Appendix F: New Endpoints Quick Reference

### Phase 1: Foundation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config/versions` | List config versions |
| GET | `/api/config/versions/{id}` | Get specific version |
| POST | `/api/config/versions/{id}/restore` | Restore version |
| DELETE | `/api/config/versions/{id}` | Delete version |
| POST | `/api/config/validate` | Validate config |
| POST | `/api/config/preview` | Preview changes |
| GET | `/api/config/audit-log` | List audit entries |
| GET | `/api/config/audit-log/{id}` | Get audit entry |
| POST | `/api/system/workers/{id}/restart` | Restart worker |

### Phase 2: Security

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config/tls` | Get TLS config |
| PUT | `/api/config/tls` | Update TLS config |
| POST | `/api/config/tls/cert/validate` | Validate certificate |
| GET | `/api/config/http` | Get HTTP config |
| PUT | `/api/config/http` | Update HTTP config |
| GET | `/api/config/security` | Get security config |
| PUT | `/api/config/security` | Update security config |
| GET | `/api/config/admin-security` | Get admin security |
| PUT | `/api/config/admin-security` | Update admin security |

### Phase 3: Performance

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config/rate-limits` | Get rate limit config |
| PUT | `/api/config/rate-limits` | Update rate limit config |
| GET | `/api/config/bot-detection` | Get bot detection config |
| PUT | `/api/config/bot-detection` | Update bot detection config |
| POST | `/api/config/bot-detection/rules` | Add bot rule |
| PUT | `/api/config/bot-detection/rules/{id}` | Update bot rule |
| DELETE | `/api/config/bot-detection/rules/{id}` | Delete bot rule |
| GET | `/api/config/traffic-shaping` | Get traffic shaping config |
| PUT | `/api/config/traffic-shaping` | Update traffic shaping config |

### Phase 4: Features

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config/dns` | Get DNS config (feature-gated) |
| PUT | `/api/config/dns` | Update DNS config |
| GET | `/api/config/dns/zones` | List DNS zones |
| POST | `/api/config/dns/zones` | Add DNS zone |
| GET | `/api/config/tunnel` | Get tunnel config |
| PUT | `/api/config/tunnel` | Update tunnel config |
| POST | `/api/config/tunnel/connect` | Connect tunnel |
| POST | `/api/config/tunnel/disconnect` | Disconnect tunnel |
| GET | `/api/config/mesh` | Get mesh config |
| PUT | `/api/config/mesh` | Update mesh config |
| GET | `/api/config/plugins` | Get plugin config |
| PUT | `/api/config/plugins` | Update plugin config |
| GET | `/api/plugins` | List plugins |
| POST | `/api/plugins` | Install plugin |
| DELETE | `/api/plugins/{id}` | Uninstall plugin |
| POST | `/api/plugins/{id}/enable` | Enable plugin |
| POST | `/api/plugins/{id}/disable` | Disable plugin |

---

## Appendix G: Glossary

| Term | Definition |
|------|------------|
| **Admin Panel** | Web interface and API for managing MaluWAF configuration |
| **Config Version** | Snapshot of configuration at a point in time, stored with metadata |
| **Dry-Run** | Validation of configuration changes without applying them |
| **Audit Log** | Immutable record of all configuration changes |
| **IPC** | Inter-Process Communication via Unix domain sockets |
| **Feature Gate** | Conditional compilation using Cargo features (e.g., `dns`) |
| **Config Section** | A subsection of the main configuration (e.g., TLS, HTTP) |
| **Validation** | Checking configuration for correctness before applying |
| **Rollback** | Restoring configuration to a previous version |
| **Hot Reload** | Applying configuration changes without restarting processes |
