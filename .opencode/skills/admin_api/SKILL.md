---
name: admin_api
description: Admin API patterns for config management, versioning, system monitoring, and operational control. Use when working with admin REST endpoints, config handlers, or system status APIs.
---

# Admin API Patterns

This skill covers the Admin API implementation patterns for SynVoid, including config handlers, versioning, and status retrieval.

**Note**: This codebase uses utoipa 5 (upgraded from utoipa 4 on 2026-04-26). Some API changes apply:
- OpenAPI tests use `HttpMethod` enum instead of `PathItemType`
- Complex config types (MainConfig, MeshConfig, DnsConfig, etc.) use `serde_json::Value` in request/response types

## Overview

The Admin API provides REST endpoints for configuration management, system monitoring, and operational control. It is located in `src/admin/` with handlers in `src/admin/handlers/`.

**Ownership (Phase 21, `architecture/admin_root_ownership.md`)**: root
`admin` is `keep_app_root` Axum transport/composition — route registration,
middleware ordering, operator-identity extraction, response adaptation, and
explicit typed service wiring via `AdminState`. Reusable transport-neutral
logic (auth primitives, rate limiting, schema helpers, the
`AdminStateProvider` narrow trait, and the `logs`/`probes`/`stats`/`system`/
`common` handler logic) lives in the `synvoid-admin` crate: put new shared
DTOs and transport-neutral handler logic there, and keep root handlers thin
adapters over typed manager operations returning `AdminMutationResult` plus
`AdminAuditEvent`.

## Core Components

### AdminState (`src/admin/state.rs`)

The shared state for all admin handlers — explicit typed-handle composition
(no service locator). `AdminState` implements
`synvoid_admin::handlers::state::AdminStateProvider` so crate-owned handlers
consume it through a narrow trait:

```rust
pub struct AdminState {
    pub metrics: MetricsState, // broadcasters, history, request logs
    pub waf_tracking: WafTrackingState, // probe/word/upstream/threat/rule-feed handles
    pub security: SecurityState, // admin token, sessions, CSRF stores
    pub mesh: MeshState, // mesh transport / org-key / audit handles
    pub honeypot: HoneypotState, // honeypot controller/runner, ICMP filter
    pub process: ProcessState, // config, process/plugin/alert managers
    pub plugins: PluginsState, // plugin reload log
    pub audit: AuditState,
    pub config_versions: ConfigVersionManager,
    pub secure_cookie: bool,
}
```

### ConfigVersionManager (`src/admin/audit.rs`)

Tracks configuration versions and enables rollback (synchronous API):

```rust
pub struct ConfigVersionManager { /* versions_dir: PathBuf, ... */ }

impl ConfigVersionManager {
    pub fn save_version(&self, toml_content: &str, description: Option<String>) -> Result<ConfigVersion, String>;
    pub fn list_versions(&self) -> Vec<ConfigVersion>;
    pub fn get_version(&self, id: &str) -> Option<ConfigVersion>;
    pub fn get_version_content(&self, id: &str) -> Option<String>;
    pub fn rollback(&self, id: &str, target_path: &PathBuf) -> Result<(), String>;
}
```

**Endpoints:**
- `GET /config/versions` - List all versions
- `GET /config/versions/{id}` - Get version content
- `POST /config/rollback/{id}` - Rollback to version

## Config Handlers Pattern

### Adding a New Config Handler

1. **Define request/response types** in handler file:

```rust
#[derive(Debug, Deserialize, ToSchema)]
pub struct MyConfigRequest {
    pub enabled: bool,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MyConfigResponse {
    pub enabled: bool,
    pub timeout_secs: u64,
}
```

2. **Add GET handler**:

```rust
#[utoipa::path(
    get,
    path = "/my-feature/config",
    responses(
        (status = 200, description = "MyFeature config", body = MyConfigResponse),
    ),
    tag = "my-feature"
)]
pub async fn get_my_feature_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MyConfigResponse>, StatusCode> {
    let config = state.config.read().await;
    Ok(Json(MyConfigResponse {
        enabled: config.main.my_feature.enabled,
        timeout_secs: config.main.my_feature.timeout_secs,
    }))
}
```

3. **Add PUT handler** (must return a typed `AdminMutationResult` and emit an
`AdminAuditEvent` — see "Typed Mutation Results" below; save a config
snapshot first):

```rust
#[utoipa::path(
    put,
    path = "/my-feature/config",
    request_body = MyConfigRequest,
    responses(
        (status = 200, description = "Config updated"),
    ),
    tag = "my-feature"
)]
pub async fn update_my_feature_config(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<MyConfigRequest>,
    _auth: OptionalAuth,
) -> Result<Json<()>, StatusCode> {
    // Save snapshot BEFORE making changes
    state.config_versions.save_version(
        &state.config.main.to_toml(),
        Some("before my_feature update")
    ).ok();

    // Apply changes through the canonical config owner, then return a typed
    // AdminMutationResult and emit an AdminAuditEvent (never ad-hoc JSON).
    // ...

}
```

4. **Register routes** in the matching family builder in `src/admin/routes.rs`
   (Phase 04; `build_router_from_state()` in `src/admin/mod.rs` only merges
   families and applies middleware):

```rust
// Always-available family, e.g. config_routes()
pub(crate) fn config_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/my-feature/config", get(get_my_feature_config))
        .route("/my-feature/config", put(update_my_feature_config))
}

// Feature-gated family — gate lives here, not in mod.rs
#[cfg(feature = "mesh")]
pub(crate) fn mesh_routes() -> Router<Arc<AdminState>> {
    Router::new().route("/mesh/specific", get(handler))
}
```

**Important**: Auth middleware is applied to the `/api` nest, not individual routes. Public routes (health, OpenAPI) are exempted by path in the auth middleware.

## Supervisor Status Pattern

The Supervisor manages worker lifecycle and exposes status via the Admin API. Use `get_supervisor` / `get_supervisor_status` handlers to read supervisor state (the old "Overseer" terminology has been fully replaced by "Supervisor").

## DefaultsConfig Sub-configs

All 24 DefaultsConfig sub-configs now have GET/PUT handlers at `/config/defaults/{subconfig}`:

| Endpoint | Config Field |
|---------|-------------|
| `/config/defaults/honeypot` | `defaults.honeypot` |
| `/config/defaults/blocked` | `defaults.blocked` |
| `/config/defaults/suspicious-words` | `defaults.suspicious_words` |
| `/config/defaults/upstream-errors` | `defaults.upstream_errors` |
| `/config/defaults/error-pages` | `defaults.error_pages` |
| `/config/defaults/css-challenge` | `defaults.css_challenge` |
| `/config/defaults/pow-challenge` | `defaults.pow_challenge` |
| `/config/defaults/challenge` | `defaults.challenge` |
| `/config/defaults/auth` | `defaults.auth` |
| `/config/defaults/worker-pool` | `defaults.worker_pool` |
| `/config/defaults/persistence` | `defaults.persistence` |
| `/config/defaults/tarpit` | `defaults.tarpit` |
| `/config/defaults/upload` | `defaults.upload` |
| `/config/defaults/traffic-shaping` | `defaults.traffic_shaping` |
| `/config/defaults/asn-scraping` | `defaults.asn_scraping` |

Also covered: ratelimit, bot, tcp, udp, theme (pre-existing handlers)

## Manual ToSchema Implementation

For types containing fields that cannot derive `ToSchema` (like `DateTime<Utc>`, `PathBuf`, or complex config types), use manual implementations in `src/admin/schema.rs`:

```rust
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use utoipa::{PartialSchema, ToSchema};

pub struct DateTimeUtc(pub DateTime<Utc>);

impl PartialSchema for DateTimeUtc {
    fn schema() -> RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .format(Some(utoipa::openapi::schema::SchemaFormat::KnownFormat(
                utoipa::openapi::KnownFormat::DateTime,
            )))
            .into()
    }
}
```

For complex config types in request/response, use `serde_json::Value`:

```rust
#[derive(Debug, Serialize, ToSchema)]
pub struct MeshConfigResponse {
    pub config: serde_json::Value,
}
```

## Mesh Admin Endpoints

The mesh admin handlers (`src/admin/handlers/mesh_admin.rs`) provide Raft and DHT status endpoints:

### Raft Status Endpoint

- `GET /api/mesh/raft/status` - Returns Raft cluster status

Returns `RaftStatusResponse`:
```rust
pub struct RaftStatusResponse {
    pub node_id: u64,
    pub leader_id: Option<u64>,
    pub term: u64,
    pub last_log_index: u64,
    pub last_applied_index: u64,
    pub membership: Vec<u64>,
    pub is_leader: bool,
    pub state: String,
}
```

### DHT Stats Endpoint

- `GET /api/mesh/dht/stats` - Returns DHT statistics

Returns `DhtStatsResponse`:
```rust
pub struct DhtStatsResponse {
    pub node_id: String,
    pub total_peers: usize,
    pub bucket_count: usize,
    pub record_count: usize,
    pub pending_announces: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
}
```

**Important**: When implementing handlers that access `parking_lot::RwLock` guards across await points, ensure the guard is dropped before the await. The guard type is `!Send` and holding it across await will cause a compilation error with `#[axum::debug_handler]`.

## Testing

```bash
# Integration tests
cargo test --test integration_test

# Test specific endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/config/versions
```

## Authentication and Session Model

The Admin API uses a **hybrid authentication model** with two distinct client classes:

### Bearer Token (API Clients)
- Send `Authorization: Bearer <token>` header
- Bypasses CSRF validation (API clients don't need it)
- Rate limited and lockout-protected
- Suitable for CLI, curl, scripts, and non-browser automation

### Session + CSRF (Browser Clients)
1. **Login**: `POST /api/auth/session` with bearer token → receives session cookie (`HttpOnly`, `SameSite=Strict`, optionally `Secure`)
2. **Session restore**: On page reload, `GET /api/auth/csrf` with session cookie → returns new CSRF token (no bearer token needed)
3. **Mutating requests**: Include `X-CSRF-Token` header and session cookie
4. **Logout**: `DELETE /api/auth/session` → invalidates session and all associated CSRF tokens

**Critical**: After session creation, the browser must **never** retain the raw bearer token in `localStorage`, `sessionStorage`, cookies, or any JavaScript-readable storage. The bearer token is used once for session exchange and then discarded.

### Session Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/session` | POST | Exchange bearer token for session cookie |
| `/api/auth/session` | DELETE | Invalidate session (logout) |
| `/api/auth/csrf` | GET | Get CSRF token for current session |

### Auth Lockout

After 5 failed auth attempts within 60 seconds, the client is locked out for 5 minutes. Lockout is enforced BEFORE bcrypt verification to prevent DoS attacks. Lockout state is keyed to the resolved client IP.

### Client IP Extraction

The admin server uses `ConnectInfo<SocketAddr>` for direct peer IP extraction. Trusted proxies can be configured via `admin.trusted_proxies` config. `x-forwarded-for` is only trusted when the direct peer is in the trusted proxies list. Untrusted direct peers cannot spoof client identity.

### WebSocket Authentication

WebSocket endpoints (`/api/ws/metrics`, `/api/ws/logs`) authenticate via:
1. Bearer token in `Authorization` header (API clients)
2. HttpOnly session cookie (browser clients)

The legacy `synvoid_ws_token` JavaScript-readable cookie is **not** supported. Browser WebSockets authenticate from the bounded session cookie.

### Security Headers

All admin responses include:
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` with `frame-ancestors 'none'`

### Session Expiry Handling

The admin-ui frontend handles both `401` and `403` as session expiry, clearing auth state and redirecting to login. WebSocket polling stops automatically on session expiry to prevent repeated failed requests.

## Audit Logging

All mutating operations are audit logged with:
- Action name (e.g., `config.update_main`, `worker.restart`, `mesh.ban_ip`)
- Target resource
- Client IP (from `ClientIp` extension)
- Success/failure status
- Timestamp

Audit logs are persisted to `audit.log` file in JSON Lines format (`.0600` permissions on Unix). Recent entries are loaded on startup for in-memory access.

### High-Impact Handler Audit Checklist

Mutating operations in these handlers include audit logging:
- `config.rs` - config updates, reload, import
- `system.rs` - worker scale/restart
- `mesh_admin.rs` - ban/unban, organization creation
- `yara_rules.rs` - submit, approve, reject, broadcast
- `plugins.rs` - plugin reload
- `honeypot.rs` - control, config updates
- `sites.rs` - site CRUD
- `alerting.rs` - alert config updates, test webhook

## Metrics Export

Prometheus metrics are exported on `127.0.0.1:9090/metrics` when `config.main.metrics.enabled` is true.

Key admin metrics:
- `synvoid_admin_auth_failures_total`
- `synvoid_admin_auth_lockouts_total`
- `synvoid_admin_rate_limited_total`
- `synvoid_admin_csrf_failures_total`
- `synvoid_admin_audit_write_failures_total`
- `synvoid_admin_ws_clients` (gauge)
- `synvoid_admin_alert_delivery_success_total`
- `synvoid_admin_alert_delivery_failure_total`

## Health Status

Site/backend health is reported as enum values (`healthy`, `unhealthy`, `unknown`) rather than optimistic boolean defaults. Freshness is indicated via `metrics_timestamp_ms` field.

## Request Log Redaction

Request logs redact sensitive query parameters: `token`, `secret`, `password`, `key`, `authorization`, `session`, `csrf`, etc.

## Typed Mutation Results (Phase 6, Phase 12 Complete)

All mutating admin endpoints must return `AdminMutationResult<T>` from `synvoid_core::admin_mutation`.

### Required pattern for mutating handlers:

```rust
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult,
    AdminMutationStatus, BlockMutationTarget, PropagationStatus,
};

// In handler:
let audit_id = uuid::Uuid::new_v4().to_string();
let audit_event = AdminAuditEvent {
    audit_id: audit_id.clone(),
    timestamp: synvoid_utils::safe_unix_timestamp(),
    actor: AdminActor::new(AdminMutationAuthority::AdminManual),
    action: "block_ip".to_string(),
    target_kind: "ip".to_string(),
    target_id: ip.to_string(),
    prior_state: None,
    requested_state: Some(serde_json::json!({...})),
    resulting_state: Some(serde_json::json!({...})),
    mutation_status: AdminMutationStatus::Applied,
    propagation_status: PropagationStatus::QueuedBestEffort,
    event_id: Some(event_id.clone()),
};
state.audit.log_audit_event(&audit_event);

return Ok(Json(AdminMutationResult {
    status: AdminMutationStatus::Applied,
    target: BlockMutationTarget { kind: "ip".to_string(), value: ip.to_string(), site_scope: Some(scope) },
    local_store_mutated: true,
    propagation: PropagationStatus::QueuedBestEffort,
    event_id: Some(event_id),
    audit_id: Some(audit_id),
    message: "IP blocked successfully".to_string(),
}));
```

### Forbidden patterns:
- `Json(json!({"success": true, ...}))` — use `AdminMutationResult` instead
- `StatusCode::OK` with ad-hoc JSON — use typed responses
- Raw session tokens in `AdminActor` — hash them first
- Defaulting to `AdminManual` authority for compatibility paths — use `CompatibilityLegacy`

### Audit logging:
- Use `state.audit.log_audit_event(&event)` for typed audit events
- Block/unblock operations must emit audit events
- Config mutations emit audit events via the typed flow