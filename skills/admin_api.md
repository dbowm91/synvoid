# Admin API Patterns

This skill covers the Admin API implementation patterns for MaluWAF, including config handlers, versioning, and status retrieval.

**Note**: This codebase uses utoipa 5 (upgraded from utoipa 4 on 2026-04-26). Some API changes apply:
- OpenAPI tests use `HttpMethod` enum instead of `PathItemType`
- Complex config types (MainConfig, MeshConfig, DnsConfig, etc.) use `serde_json::Value` in request/response types

## Overview

The Admin API provides REST endpoints for configuration management, system monitoring, and operational control. It is located in `src/admin/` with handlers in `src/admin/handlers/`.

## Core Components

### AdminState (`src/admin/state.rs`)

The shared state for all admin handlers:

```rust
pub struct AdminState {
    pub process: Arc<AdminProcessState>,
    pub config: RwLock<ConfigManager>,
    pub config_versions: ConfigVersionManager,  // Added in Wave 5.13
    // ... other fields
}
```

### ConfigVersionManager (`src/admin/audit.rs`)

Tracks configuration versions and enables rollback:

```rust
pub struct ConfigVersionManager {
    versions_dir: PathBuf,
    max_versions: usize,
}

impl ConfigVersionManager {
    pub async fn save_snapshot(&self, content: &str, description: Option<&str>) -> Result<ConfigVersion>;
    pub async fn list_versions(&self) -> Result<Vec<ConfigVersion>>;
    pub async fn get_version(&self, id: &str) -> Result<String>;
    pub async fn rollback(&self, id: &str) -> Result<()>;
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

3. **Add PUT handler** (should save snapshot first):

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
    state.config_versions.save_snapshot(
        &state.config.main.to_toml(),
        Some("before my_feature update")
    ).await.ok();
    
    // Apply changes
    state.config.write().await.main.my_feature.enabled = req.enabled;
    // ...
    
    Ok(Json(()))
}
```

4. **Register routes** in `src/admin/mod.rs`:

```rust
let api_routes = Router::new()
    .route("/my-feature/config", get(get_my_feature_config))
    .route("/my-feature/config", put(update_my_feature_config))
    // ...
```

## Overseer Status Pattern

### Writing Status (Overseer Process)

The Overseer writes status to a file periodically:

```rust
// In src/overseer/process.rs
const OVERSEER_STATUS_FILE: &str = "overseer_status.json";

struct OverseerStatusFile {
    running: bool,
    pid: Option<u32>,
    master_pid: Option<u32>,
    master_status: String,
    uptime_secs: u64,
    upgrade_mode: String,
    drain_status: String,
    workers: Vec<WorkerStatusInfo>,
    version: String,
    last_updated: u64,
}

impl OverseerProcess {
    async fn write_status_file(&self) {
        let status = self.collect_status();
        let json = serde_json::to_string_pretty(&status).unwrap();
        let path = self.runtime_dir.join(OVERSESEER_STATUS_FILE);
        // Write atomically via temp file
        tokio::fs::write(&temp_path, json).await;
        tokio::fs::rename(&temp_path, &path).await;
    }
}
```

### Reading Status (Admin Handler)

```rust
// In src/admin/handlers/system.rs
fn get_overseer_status_file_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run"))
        .join("maluwaf")
        .join("overseer_status.json")
}

pub async fn get_overseer(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<OverseerStatusResponse>, StatusCode> {
    let path = get_overseer_status_file_path();
    
    if path.exists() {
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            if let Ok(json) = serde_json::from_str::<Value>(&content) {
                return Ok(Json(OverseerStatusResponse {
                    running: json.get("running").and_then(|v| v.as_bool()).unwrap_or(false),
                    // ... map other fields
                }));
            }
        }
    }
    
    // Fallback to ProcessManager state
    // ...
}
```

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

## Testing

```bash
# Integration tests
cargo test --test integration_test

# Test specific endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/config/versions
```