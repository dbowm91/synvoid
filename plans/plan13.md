# MaluWAF Implementation Plan - Wave 13

**Web Application Stack: Static Sites, PHP, FastCGI, WASM, and Granian Deployment**

**Status**: Draft - Pending Implementation
**Last Updated**: 2026-04-27
**Source Investigation**: Comprehensive code review of directory listing, theme system, Spin/Fermyon, Granian supervisor pattern, WASM architecture, and router integration

---

## Investigation Summary

This plan addresses findings from a comprehensive review of the web application deployment infrastructure covering:

- **Directory Listing** (`src/static_files/mod.rs`, `src/theme/dir_listing.rs`)
- **Theme System** (`src/theme/config.rs`, `src/theme/renderer.rs`, `admin-ui/src/pages/site_editor.rs`)
- **Spin WASM Runtime** (Fermyon framework research and architecture planning)
- **Granian Supervisor Pattern** (`src/app_server/granian.rs`, `src/app_server/mod.rs`)
- **WASM Architecture** (`src/plugin/wasm_runtime.rs`, `src/serverless/`)
- **Router Integration** (`src/router.rs`, `src/http/server.rs`)

---

## Part 1: Static Websites with Theme-Aware Directory Listing

### Current State

**Backend Support** (fully implemented):
- `SiteStaticConfig` has `directory_listing`, `directory_listing_format`, `theme` fields
- `SiteStaticThemeConfig` allows per-location theme overrides with `directory_template_path`
- `StaticFileHandler` applies theme via `serve_directory()` method
- `DirectoryListingTemplate` renders complete HTML with theme CSS

**Admin UI** (incomplete):
- `StaticTab` in site_editor.rs (lines 1586-1613) is minimal with only basic toggle and input fields
- **Missing**: Directory listing configuration, theme settings, per-location overrides, preview
- Frontend has **duplicated preset colors** in `get_preset_colors()` (lines 895-1008 in site_editor.rs)

**Key Files**:
| File | Purpose |
|------|---------|
| `src/config/site/static_files.rs` | SiteStaticConfig, StaticLocation, SiteStaticThemeConfig |
| `src/static_files/mod.rs` | StaticFileHandler, serve_directory() |
| `src/theme/dir_listing.rs` | DirectoryListingTemplate, render() |
| `src/theme/renderer.rs` | generate_directory_listing_css() |
| `admin-ui/src/pages/site_editor.rs` | StaticTab (needs enhancement) |
| `admin-ui/src/types/mod.rs` | ThemeResponse, ThemeColors types |
| `admin-ui/src/services/api.rs` | API service methods |
| `src/admin/handlers/sites.rs` | Backend handlers (need new endpoints) |

### Implementation

#### 1.1 Backend API Enhancement

**New endpoints to add in `src/admin/handlers/sites.rs`**:

```
GET  /api/sites/{site_id}/static         → SiteStaticConfigResponse
PUT  /api/sites/{site_id}/static         → UpdateSiteStaticConfigRequest
GET  /api/sites/{site_id}/static/theme   → SiteStaticThemeResponse
PUT  /api/sites/{site_id}/static/theme   → UpdateSiteStaticThemeRequest
```

**New types to add**:
```rust
// Request/Response types for static config
pub struct SiteStaticConfigResponse {
    pub site_id: String,
    pub enabled: Option<bool>,
    pub default_root: Option<String>,
    pub directory_listing: Option<bool>,
    pub directory_listing_format: Option<String>,
    pub theme: Option<SiteStaticThemeResponse>,
    pub locations: Vec<StaticLocationResponse>,
}

pub struct SiteStaticThemeResponse {
    pub preset: Option<String>,
    pub mode: Option<String>,
    pub allow_only: Option<String>,
    pub colors: Option<ThemeColorsOverride>,
    pub directory_template_path: Option<String>,
}

pub struct StaticLocationResponse {
    pub path: String,
    pub root: String,
    pub index: Option<String>,
    pub cache_ttl: Option<u64>,
    pub theme: Option<SiteStaticThemeResponse>,
}

pub struct UpdateSiteStaticConfigRequest {
    pub enabled: Option<bool>,
    pub default_root: Option<String>,
    pub directory_listing: Option<bool>,
    pub directory_listing_format: Option<String>,
    pub theme: Option<UpdateSiteStaticThemeRequest>,
}

pub struct UpdateSiteStaticThemeRequest {
    pub preset: Option<String>,
    pub mode: Option<String>,
    pub allow_only: Option<String>,
    pub colors: Option<ThemeColorsOverride>,
    pub directory_template_path: Option<String>,
}
```

**Handler implementations**:
- `get_site_static_config()` - Read static config from SiteConfig
- `update_site_static_config()` - Merge updates into SiteConfig, persist
- `get_site_static_theme()` - Return only theme portion
- `update_site_static_theme()` - Update theme fields only

#### 1.2 Frontend Types Enhancement

**Files to modify**: `admin-ui/src/types/mod.rs`

**New TypeScript types**:
```typescript
// Static configuration types
pub struct SiteStaticConfigResponse {
    pub site_id: String,
    pub enabled: Option<bool>,
    pub default_root: Option<String>,
    pub directory_listing: Option<bool>,
    pub directory_listing_format: Option<String>,
    pub theme: Option<SiteStaticThemeResponse>,
    pub locations: Vec<StaticLocationResponse>,
}

pub struct SiteStaticThemeResponse {
    pub preset: Option<String>,
    pub mode: Option<String>,
    pub allow_only: Option<String>,
    pub colors: Option<ThemeColorsOverride>,
    pub directory_template_path: Option<String>,
}

pub struct StaticLocationResponse {
    pub path: String,
    pub root: String,
    pub index: Option<String>,
    pub cache_ttl: Option<u64>,
    pub theme: Option<SiteStaticThemeResponse>,
}
```

#### 1.3 API Service Methods

**Files to modify**: `admin-ui/src/services/api.rs`

**New methods to add**:
```typescript
pub async fn get_site_static_config(&self, site_id: &str) -> Result<SiteStaticConfigResponse, String>
pub async fn update_site_static_config(&self, site_id: &str, request: &serde_json::Value) -> Result<SiteStaticConfigResponse, String>
pub async fn get_site_static_theme(&self, site_id: &str) -> Result<SiteStaticThemeResponse, String>
pub async fn update_site_static_theme(&self, site_id: &str, request: &serde_json::Value) -> Result<SiteStaticThemeResponse, String>
```

**Pattern to follow**: Use existing `get_site_error_pages()` and `update_site_error_pages()` as reference.

#### 1.4 StaticTab Enhancement

**Files to modify**: `admin-ui/src/pages/site_editor.rs` (lines 1586-1613)

**Current StaticTab is minimal - complete rewrite needed**:

```
StaticTab Layout:
├── Static File Serving
│   ├── [Toggle] Enable Static File Serving
│   ├── [Input] Document Root
│   └── [Input] Index File
│
├── Directory Listing
│   ├── [Toggle] Enable Directory Listing
│   ├── [Select] Format: HTML / JSON
│   └── [Input] Custom Template Path (optional)
│
├── Theme Settings (expandable)
│   ├── [Select] Theme Preset: default, dark, light, ocean, forest, sunset
│   ├── [Select] Mode: auto, dark, light
│   ├── [Select] Allow Only: both, dark only, light only
│   │
│   └── Custom Colors (optional, expandable)
│       ├── Dark Background [Color]
│       ├── Dark Surface [Color]
│       ├── Dark Primary [Color]
│       └── ... (all ThemeColors fields)
│
├── Locations (expandable list)
│   └── [Per-location configuration with theme overrides]
│       └── [Location row]
│           ├── Path: /files
│           ├── Root: /var/www/files
│           ├── [Toggle] Enable Directory Listing (override)
│           ├── [Select] Format (override)
│           └── [Input] Template Path (override)
│
└── Caching
    ├── [Input] Cache Max Age
    └── [Toggle] ETag
```

**Key component structure**:
```typescript
#[function_component]
fn StaticTab(props: &StaticTabProps) -> Html {
    let enabled = use_state(|| false);
    let default_root = use_state(|| String::new());
    let directory_listing = use_state(|| false);
    let directory_format = use_state(|| "html".to_string());
    let theme_preset = use_state(|| "default".to_string());
    let preview_html = use_state(|| String::new());
    // ... more state

    // Load config on mount
    use_effect_with((), {
        let enabled = enabled.clone();
        // ...
        async move {
            let api = ApiService::new();
            if let Ok(config) = api.get_site_static_config(&props.site_id).await {
                enabled.set(config.enabled.unwrap_or(false));
                // ... set other state
            }
        }
    });

    // Preview generation
    let generate_preview = {
        let theme_preset = theme_preset.clone();
        let preview_html = preview_html.clone();
        Callback::from(move |_| {
            let colors = get_preset_colors(&theme_preset);
            let html = generate_directory_listing_preview(&colors);
            preview_html.set(html);
        })
    };

    html! {
        <div class="space-y-6">
            // Section: Enable Static Serving
            // Section: Directory Listing
            // Section: Theme Settings with preview iframe
            // Section: Locations list
            // Section: Caching
        </div>
    }
}
```

#### 1.5 Preview Component

**Pattern from ErrorPagesTab** (lines 861-878 in site_editor.rs):

```typescript
fn generate_directory_listing_preview(
    colors: &ThemeColorsResponse,
    use_light: bool,
) -> String {
    let c = if use_light { &colors.light } else { &colors.dark };

    // Sample directory with files/folders
    format!(r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        :root {{
            --waf-bg: {bg};
            --waf-surface: {surface};
            --waf-primary: {primary};
            --waf-text: {text};
            --waf-border: {border};
            --waf-accent: {accent};
        }}
        body {{
            font-family: system-ui, sans-serif;
            background-color: var(--waf-bg);
            color: var(--waf-text);
            padding: 2rem;
        }}
        .waf-dir-title {{ color: var(--waf-primary); }}
        .waf-dir-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--waf-surface);
            border: 1px solid var(--waf-border);
            border-radius: 8px;
        }}
        .waf-dir-table th {{
            text-align: left;
            padding: 0.75rem;
            background: {accent};
            color: var(--waf-primary);
        }}
        .waf-dir-table td {{
            padding: 0.75rem;
            border-bottom: 1px solid var(--waf-border);
        }}
    </style>
</head>
<body>
    <h1 class="waf-dir-title">Index of /documents/</h1>
    <table class="waf-dir-table">
        <thead><tr><th>Name</th><th>Modified</th><th>Size</th></tr></thead>
        <tbody>
            <tr>
                <td>../</td><td>Apr 27, 2026</td><td>-</td>
            </tr>
            <tr>
                <td>projects/</td><td>Apr 27, 2026</td><td>-</td>
            </tr>
            <tr>
                <td>readme.md</td><td>Apr 27, 2026</td><td>2.4 KB</td>
            </tr>
        </tbody>
    </table>
</body>
</html>
"#,
        bg = c.background,
        surface = c.surface,
        primary = c.primary,
        text = c.text,
        border = c.border,
        accent = c.accent,
    )
}
```

**Preview iframe** (same pattern as ErrorPagesTab):
```html
<iframe
    srcdoc={(*preview_html).clone()}
    class="w-full h-96"
    sandbox="allow-same-origin"
/>
```

### Files Summary - Part 1

| Layer | File | Change Type | Lines |
|-------|------|-------------|-------|
| Backend | `src/admin/handlers/sites.rs` | Add handlers & types | ~250 |
| Frontend Types | `admin-ui/src/types/mod.rs` | Add TypeScript types | ~50 |
| API Service | `admin-ui/src/services/api.rs` | Add methods | ~100 |
| StaticTab | `admin-ui/src/pages/site_editor.rs` | Complete rewrite | ~400 |

**Estimation: ~800 lines total**

---

## Part 2: Spin (Fermyon) WASM Runtime Support

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     WAF Core (MaluWAF)                       │
├─────────────────────────────────────────────────────────────┤
│  BackendType::Spin → SpinSupervisor → spin up (CLI)          │
│                                                              │
│  Unix Socket HTTP ← reverse proxy                           │
│                                                              │
│  src/app_server/spin.rs (NEW)                                │
│    └── SpinSupervisor (process management)                  │
│    └── SpinConfig (configuration)                          │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                  Spin Runtime (external)                     │
│  spin up --socket /path/to/socket                           │
│    └── spin.toml manifest                                   │
│    └── WASM components with Ferris HTTP handlers             │
└─────────────────────────────────────────────────────────────┘
```

### Key Research Findings

**Spin HTTP Interface**:
- Uses WebAssembly Component Model with `wasi-http` specification
- Handler signature: `handle: func(request: incoming-request, response-out: response-outparam)`
- Multi-language SDKs: Rust, JS/TS, Python, Go
- Built-in routing, triggers, static assets via spin.toml

**Spin vs Raw WASMtime**:
- Spin is a **framework** that uses wasmtime as execution engine
- Adds application lifecycle, component composition, resource permissioning
- Health check endpoint: `/.well-known/spin/health`

**Granian Supervisor Pattern to Follow**:
- Same process lifecycle management (spawn, health check, restart, shutdown)
- Same Unix socket HTTP proxying
- Similar auto-install mechanism (cargo install spin)

### Implementation - Phase 2A: Spin Supervisor

#### 2.1 SpinConfig Schema

**New file**: `src/config/site/spin.rs`

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteSpinConfig {
    #[serde(default)]
    pub enabled: Option<bool>,

    #[serde(default)]
    pub app_path: Option<String>,

    #[serde(default)]
    pub workers: Option<u32>,

    #[serde(default)]
    pub socket_path: Option<String>,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub host: Option<String>,

    #[serde(default)]
    pub rust_path: Option<String>,

    #[serde(default)]
    pub working_directory: Option<String>,

    #[serde(default)]
    pub env: Option<std::collections::HashMap<String, String>>,

    #[serde(default)]
    pub restart_on_failure: Option<bool>,

    #[serde(default)]
    pub max_restarts: Option<u32>,

    #[serde(default)]
    pub health_check_path: Option<String>,

    #[serde(default)]
    pub health_check_interval_secs: Option<u64>,

    #[serde(default)]
    pub health_check_timeout_secs: Option<u64>,

    #[serde(default = "default_some_true")]
    pub auto_install_spin: Option<bool>,

    #[serde(default = "default_some_true")]
    pub auto_detect_manifest: Option<bool>,

    #[serde(default)]
    pub log_level: Option<String>,

    #[serde(default)]
    pub log_format: Option<String>,

    #[serde(default)]
    pub log_verbose: Option<bool>,
}

fn default_some_true() -> Option<bool> {
    Some(true)
}

impl SiteSpinConfig {
    pub fn validate(&self) -> Result<(), crate::config::validation::ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.app_path.is_none() && !self.auto_detect_manifest.unwrap_or(true) {
                return Err(crate::config::validation::ConfigValidationError {
                    field: "spin.app_path".to_string(),
                    message: "App path or auto-detect required when Spin is enabled".to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn socket_path_for_site(&self, site_id: &str, worker_id: usize) -> std::path::PathBuf {
        if let Some(ref path) = self.socket_path {
            std::path::PathBuf::from(path)
        } else {
            std::env::temp_dir().join(format!("maluwaf-{}-spin-{}.sock", site_id, worker_id))
        }
    }
}
```

#### 2.2 Spin Runtime Config

**New file**: `src/app_server/spin.rs`

**Core structs**:
```rust
#[derive(Clone)]
pub struct SpinConfig {
    pub app_path: String,
    pub runtime_path: Option<PathBuf>,
    pub workers: u32,
    pub socket_path: Option<PathBuf>,
    pub port: Option<u16>,
    pub host: Option<String>,
    pub rust_path: Option<PathBuf>,
    pub working_directory: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub restart_on_failure: bool,
    pub max_restarts: u32,
    pub health_check_interval_secs: u64,
    pub health_check_timeout_secs: u64,
    pub auto_install_spin: bool,
    pub auto_detect_manifest: bool,
    pub log_level: SpinLogLevel,
    pub log_format: SpinLogFormat,
    pub log_verbose: bool,
    pub site_id: String,
    pub worker_id: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpinLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<&str> for SpinLogLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "error" => SpinLogLevel::Error,
            "warn" => SpinLogLevel::Warn,
            "info" => SpinLogLevel::Info,
            "debug" => SpinLogLevel::Debug,
            "trace" => SpinLogLevel::Trace,
            _ => SpinLogLevel::Info,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpinLogFormat {
    Text,
    Json,
}

impl From<&str> for SpinLogFormat {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => SpinLogFormat::Json,
            _ => SpinLogFormat::Text,
        }
    }
}

pub struct SpinSupervisor {
    config: Arc<SpinConfig>,
    child: Arc<TokioRwLock<Option<tokio::process::Child>>>,
    healthy: RunningFlag,
    restart_count: Arc<AtomicU32>,
    consecutive_failures: Arc<AtomicU32>,
    consecutive_successes: Arc<AtomicU64>,
    shutdown_tx: broadcast::Sender<()>,
    running: RunningFlag,
    pid: Arc<AtomicU32>,
    log_buffer: Arc<RwLock<Vec<String>>>,
}
```

**Key methods to implement**:

| Method | Purpose |
|--------|---------|
| `SpinSupervisor::new(config: SpinConfig) -> Self` | Constructor |
| `start(&self) -> impl Future<Output = Result<(), String>>` | Spawn spin process |
| `stop(&self) -> impl Future<Output = ()>` | Graceful shutdown |
| `restart(&self) -> Result<(), String>` | Restart on failure |
| `check_health(&self) -> impl Future<Output = bool>` | Health check |
| `forward_request(...) -> impl Future<Output = Result<Response<Bytes>, String>>` | HTTP proxy |
| `get_logs(&self) -> Vec<String>` | Log retrieval |
| `resolve_socket_path(&self) -> PathBuf` | Socket path resolution |
| `is_healthy(&self) -> bool` | Health status query |

**Auto-detection for spin.toml**:
```rust
fn detect_spin_manifest(working_dir: &Path) -> Option<PathBuf> {
    let candidates = vec![
        working_dir.join("spin.toml"),
        working_dir.join("Appfile.toml"),
    ];
    for candidate in candidates {
        if candidate.exists() {
            tracing::info!("Auto-detected Spin manifest: {}", candidate.display());
            return Some(candidate);
        }
    }
    None
}
```

**Command building** (following Granian pattern):
```rust
fn build_command(&self) -> Command {
    let spin_binary = self.config.resolve_spin_path();
    let mut cmd = Command::new(&spin_binary);
    cmd.arg("up");
    cmd.arg("--socket").arg(self.socket_path());
    cmd.arg("--workers").arg(self.config.workers.to_string());

    if let Some(ref working_dir) = self.config.working_directory {
        cmd.current_dir(working_dir);
    }

    for (key, value) in &self.config.env {
        cmd.env(key, value);
    }

    cmd.kill_on_drop(true);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd
}
```

**Socket health check** (same pattern as Granian):
```rust
async fn check_health(&self) -> bool {
    let socket_path = self.config.resolve_socket_path();
    let connect_future = tokio::net::UnixStream::connect(&socket_path);
    match tokio::time::timeout(
        Duration::from_secs(self.config.health_check_timeout_secs),
        connect_future,
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
```

#### 2.3 Spin Module Registration

**Modify**: `src/app_server/mod.rs`

```rust
pub mod granian;
pub mod spin;  // ADD

pub use granian::{GranianConfig, GranianInterface, GranianLogFormat, GranianLogLevel, GranianSupervisor};
pub use spin::{SpinConfig, SpinSupervisor};  // ADD

// Spin supervisor registry (parallel to Granian)
static SPIN_SUPERVISORS: std::sync::LazyLock<RwLock<HashMap<String, Arc<SpinSupervisor>>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn register_spin_supervisor(site_id: &str, supervisor: Arc<SpinSupervisor>) {
    SPIN_SUPERVISORS.write().insert(site_id.to_string(), supervisor);
}

pub fn get_spin_supervisor(site_id: &str) -> Option<Arc<SpinSupervisor>> {
    SPIN_SUPERVISORS.read().get(site_id).cloned()
}

pub fn get_all_spin_supervisors() -> Vec<(String, Arc<SpinSupervisor>)> {
    SPIN_SUPERVISORS.read().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

pub fn get_spin_logs(site_id: &str) -> Option<Vec<String>> {
    SPIN_SUPERVISORS.read().get(site_id).map(|s| s.clone().get_logs())
}
```

#### 2.4 SiteConfig Integration

**Modify**: `src/config/site/mod.rs`

```rust
mod spin;  // ADD
pub use spin::SiteSpinConfig;

pub struct SiteConfig {
    // ... existing fields ...
    #[serde(default)]
    pub spin: SiteSpinConfig,
}

impl SiteConfig {
    // ... existing methods ...

    pub fn spin_config(&self) -> SpinConfig {
        let site_config = &self.spin;

        SpinConfig {
            app_path: site_config.app_path.clone().unwrap_or_default(),
            runtime_path: site_config.rust_path.as_ref().map(PathBuf::from),
            workers: site_config.workers.unwrap_or(1),
            socket_path: site_config.socket_path.as_ref().map(PathBuf::from),
            port: site_config.port,
            host: site_config.host.clone(),
            rust_path: site_config.rust_path.as_ref().map(PathBuf::from),
            working_directory: site_config.working_directory.as_ref().map(PathBuf::from),
            env: site_config.env.clone().unwrap_or_default(),
            restart_on_failure: site_config.restart_on_failure.unwrap_or(true),
            max_restarts: site_config.max_restarts.unwrap_or(5),
            health_check_interval_secs: site_config.health_check_interval_secs.unwrap_or(10),
            health_check_timeout_secs: site_config.health_check_timeout_secs.unwrap_or(5),
            auto_install_spin: site_config.auto_install_spin.unwrap_or(true),
            auto_detect_manifest: site_config.auto_detect_manifest.unwrap_or(true),
            log_level: site_config.log_level.as_ref()
                .map(|s| SpinLogLevel::from(s.as_str()))
                .unwrap_or(SpinLogLevel::Info),
            log_format: site_config.log_format.as_ref()
                .map(|s| SpinLogFormat::from(s.as_str()))
                .unwrap_or(SpinLogFormat::Text),
            log_verbose: site_config.log_verbose.unwrap_or(false),
            site_id: self.site_id(),
            worker_id: 0,  // Set by caller
        }
    }
}
```

### Implementation - Phase 2B: Router Integration

#### 2.5 BackendConfig Enum Extension

**Modify**: `src/config/site/backend.rs`

Add Spin variant to BackendConfig enum:
```rust
pub enum BackendConfig {
    // ... existing variants ...

    #[serde(rename = "spin")]
    Spin {
        #[serde(default)]
        runtime_path: Option<String>,
        #[serde(default)]
        socket: Option<String>,
    },
}
```

#### 2.6 BackendType Enum Extension

**Modify**: `src/router.rs` (line 55-66)

Add Spin variant:
```rust
pub enum BackendType {
    // ... existing ...
    Spin,
}
```

#### 2.7 Router Extension

**Modify**: `src/router.rs`

In `get_location_backend()` and `route_to_target()`, add handling for `BackendConfig::Spin`:

```rust
BackendConfig::Spin { runtime_path, socket } => {
    let socket = socket.clone().unwrap_or_else(|| {
        site_config.spin.socket_path_for_site(&site_id, 0).display().to_string()
    });
    RouteResult::Found(RouteTarget {
        site_id: Arc::from(site_id.as_str()),
        upstream: Arc::from(format!("http://unix:{}:", socket)),
        site_config: site_config.clone(),
        static_handler: None,
        backend_type: BackendType::Spin,
        backend_socket: Some(Arc::from(socket.as_str())),
        backend_plugin: None,
        tunnel_peer: None,
        tunnel_port: None,
        serverless_function: None,
        php_location_config: None,
    })
}
```

In `route_to_target()`, add site-level Spin fallback:
```rust
// After AppServer handling, add:
if site_config.spin.enabled.unwrap_or(false) {
    let socket = site_config.spin.socket_path_for_site(&site_id, 0).display().to_string();
    return RouteResult::Found(RouteTarget {
        site_id: Arc::from(site_id.as_str()),
        upstream: Arc::from(format!("http://unix:{}:", socket)),
        site_config: site_config.clone(),
        static_handler: None,
        backend_type: BackendType::Spin,
        backend_socket: Some(Arc::from(socket.as_str())),
        // ... rest of fields
    });
}
```

#### 2.8 HTTP Server Handler

**Modify**: `src/http/server.rs`

Add handler for `BackendType::Spin` similar to `BackendType::AppServer`:

```rust
if matches!(target.backend_type, crate::router::BackendType::Spin) {
    if let Some(ref spin_servers) = spin_servers {
        let spin_servers_read = spin_servers.read().await;
        if let Some(supervisor) = spin_servers_read.get(&site_id) {
            let body_bytes_for_spin: Bytes = full_body_arc.as_ref().clone();
            match supervisor.forward_request(
                method,
                &parts.uri.to_string(),
                &parts.headers,
                body_bytes_for_spin,
            )
            .await
            {
                Ok(response) => return Ok(response.map(|b| Full::new(b).boxed())),
                Err(e) => {
                    tracing::warn!("Spin error for site {} path {}: {}", site_id, path, e);
                    return Ok(Self::build_response_with_alt_svc(
                        502,
                        format!("Backend Error: {}", e),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }
            }
        }
    }
}
```

Also add WebSocket support for Spin (pattern from Granian at lines 1665-1685):
```rust
if matches!(target.backend_type, crate::router::BackendType::Spin) {
    if let Some(supervisor) = servers_read.get(&site_id) {
        let socket_path = supervisor.config().resolve_socket_path();
        // handle_websocket_to_spin()
    }
}
```

#### 2.9 UnifiedServer Initialization

**Modify**: `src/worker/unified_server.rs` (around lines 390-421)

Add Spin supervisor initialization alongside Granian:
```rust
// Spin initialization
let spin_config = site_config.spin_config();
if spin_config.is_valid() {
    let mut spin_cfg = spin_config;
    spin_cfg = spin_cfg.with_site_info(site_id, worker_id);

    let supervisor = Arc::new(SpinSupervisor::new(spin_cfg));
    supervisor.start().await.map_err(|e| {
        tracing::error!("Failed to start Spin supervisor for site {}: {}", site_id, e);
    })?;

    spin_servers.write().insert(site_id.clone(), supervisor.clone());
    crate::app_server::register_spin_supervisor(site_id, supervisor);
}
```

### Files Summary - Part 2 (Spin Support)

| Layer | File | Change Type | Lines |
|-------|------|-------------|-------|
| Config | `src/config/site/spin.rs` | **NEW** | ~150 |
| Config | `src/config/site/mod.rs` | Modify | ~30 |
| Config | `src/config/site/backend.rs` | Add variant | ~10 |
| Runtime | `src/app_server/spin.rs` | **NEW** | ~700 |
| Runtime | `src/app_server/mod.rs` | Add exports | ~30 |
| Router | `src/router.rs` | Add routing | ~50 |
| HTTP | `src/http/server.rs` | Add handler | ~40 |
| Worker | `src/worker/unified_server.rs` | Add init | ~30 |

**Estimation: ~1040 lines Rust**

---

## Part 3: WASM Component Support for Spin

### Current State Analysis

**Existing WASM Architecture** (`src/plugin/wasm_runtime.rs`):
- Uses pointer-based ABI: `filter_request(ptr, len, ...)` and `handle_request(ptr, ...)`
- Manual memory management via `guest_alloc`/`guest_free`
- Host functions in `env::` namespace
- Custom binary format for headers (u16 length prefixes)

**Spin/Ferris HTTP Components**:
- Use WASI HTTP (preview2) with typed WIT interfaces
- Handler: `handle: func(request: incoming-request, response-out: response-outparam)`
- `wasi:http/types` namespace for types (IncomingRequest, Fields, IncomingBody, ResponseOutparam)
- Component model linking instead of raw WASM

**ABI Incompatibility**:
| Aspect | Current WASM | Spin Components |
|--------|--------------|-----------------|
| Data Passing | Raw pointers + lengths | Typed WIT structs |
| Headers | Custom binary format | `Fields` type with MIME parsing |
| Body | Single buffer | Streaming `IncomingBody` |
| Linkage | `env::` namespace | `wasi:http/` WIT namespace |

### Recommendation: Separate Runtime

Create `src/serverless/spin_component.rs` for Spin HTTP components:

```
src/serverless/
├── mod.rs
├── manager.rs (existing)
├── instance_pool.rs (existing)
└── spin_component.rs (NEW)
    ├── SpinComponentRuntime
    ├── SpinLinker (WASI HTTP compatible)
    └── SpinComponentInstance
```

**Key design decisions**:
1. Does NOT reuse `WasmRuntime` due to ABI differences
2. Shares underlying wasmtime Engine for compilation
3. Uses component-model linker for WIT compatibility
4. Follows same instance pooling patterns as serverless

### Implementation - Phase 3A: SpinComponentRuntime

#### 3.1 Spin Component Linker Setup

```rust
// src/serverless/spin_component.rs

use wasmtime::{
    Engine, Component, Linker, Store,
    component::Val, ResourceTransfers,
};
use wasmtime_wasi::WasiCtxBuilder;

pub struct SpinComponentRuntime {
    engine: Arc<Engine>,
    linker: Arc<Linker<SpinLinkerContext>>,
}

impl SpinComponentRuntime {
    pub fn new(engine: Engine) -> Result<Self, String> {
        let mut linker = Linker::new(&engine);

        // Add WASI HTTP imports
        wasmtime_wasi_http::add_to_linker_sync(&mut linker, |ctx| ctx)
            .map_err(|e| format!("Failed to add WASI HTTP to linker: {}", e))?;

        // Add Spin-specific imports if needed
        // (Spin SDK types, key-value store, etc.)

        Ok(Self {
            engine: Arc::new(engine),
            linker: Arc::new(linker),
        })
    }

    pub fn load_component(&self, bytes: &[u8]) -> Result<Component, String> {
        Component::from_binary(self.engine.as_ref(), bytes)
            .map_err(|e| format!("Failed to load component: {}", e))
    }

    pub async fn invoke(
        &self,
        component: &Component,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, String> {
        let mut store = self.create_store(request).await?;
        let instance = self.linker.instantiate(&mut store, component)
            .map_err(|e| format!("Failed to instantiate: {}", e))?;

        // Get the handler function
        let handler = self.linker.get(&mut store, &instance, "handle")
            .ok_or("Missing handle export")?;

        // Call with request/response params
        // ... ( WIT-compatible invocation )

        Ok(response)
    }
}
```

#### 3.2 Spin Linker Context

```rust
pub struct SpinLinkerContext {
    pub wasi: wasmtime_wasi::WasiCtx,
    pub http: wasmtime_wasi_http::WasiHttpCtx,
    pub kv: HashMap<String, Vec<u8>>,  // Spin KV store
}

impl SpinLinkerContext {
    pub fn new() -> Self {
        Self {
            wasi: WasiCtxBuilder::new().build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
            kv: HashMap::new(),
        }
    }
}
```

#### 3.3 Instance Pooling for Spin Components

```rust
pub struct SpinComponentPool {
    runtime: Arc<SpinComponentRuntime>,
    components: HashMap<String, Component>,
    instances: RwLock<HashMap<String, Vec<PooledInstance>>>,
}

pub struct PooledInstance {
    store: Store<SpinLinkerContext>,
    instance: wasmtime::Instance,
    last_used: Instant,
}

impl SpinComponentPool {
    pub async fn get_instance(&self, component_name: &str) -> Result<PooledInstance, String> {
        // Try to get from pool
        let mut instances = self.instances.write().await;
        if let Some(pool) = instances.get_mut(component_name) {
            if let Some(mut inst) = pool.pop() {
                inst.last_used = Instant::now();
                return Ok(inst);
            }
        }

        // Create new instance
        let component = self.components.get(component_name)
            .ok_or("Component not found")?;
        let store = self.runtime.create_store().await;
        let instance = self.runtime.linker.instantiate(&mut store.clone(), component)
            .map_err(|e| e.to_string())?;

        Ok(PooledInstance {
            store,
            instance,
            last_used: Instant::now(),
        })
    }
}
```

### Implementation - Phase 3B: Manager Integration

Modify `src/serverless/manager.rs` to support Spin components:

```rust
// Add to ServerlessManager
pub struct ServerlessManager {
    // ... existing fields ...
    spin_pools: RwLock<HashMap<String, Arc<SpinComponentPool>>>,
}

impl ServerlessManager {
    pub async fn load_spin_component(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), ServerlessError> {
        let runtime = self.get_or_create_spin_runtime().await?;
        let component = runtime.load_component(bytes)
            .map_err(|e| ServerlessError::InvalidWasm(e.to_string()))?;

        let pool = SpinComponentPool::new(runtime);
        pool.components.insert(name.to_string(), component);

        let mut pools = self.spin_pools.write().await;
        pools.insert(name.to_string(), Arc::new(pool));

        Ok(())
    }

    pub async fn invoke_spin_component(
        &self,
        name: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, ServerlessError> {
        let pools = self.spin_pools.read().await;
        let pool = pools.get(name)
            .ok_or(ServerlessError::FunctionNotFound)?;

        let instance = pool.get_instance(name).await
            .map_err(|e| ServerlessError::ExecutionFailed(e.to_string()))?;

        pool.runtime.invoke(&instance.component, request).await
    }
}
```

### Files Summary - Part 3 (WASM Components)

| Layer | File | Change Type | Lines |
|-------|------|-------------|-------|
| Runtime | `src/serverless/spin_component.rs` | **NEW** | ~500 |
| Manager | `src/serverless/manager.rs` | Add spin support | ~100 |

**Estimation: ~600 lines Rust (Phase 3, deferred)**

---

## Part 4: Admin UI for Spin

### New Components

**Files to modify**: `admin-ui/src/pages/site_editor.rs`

**SpinSection layout**:
```
Spin WASM Runtime
├── [Toggle] Enable Spin
├── [Input] Manifest Path (spin.toml or Spinfile.toml)
├── [Input] App Name (auto-detected from manifest)
├── [Select] Workers (default: 1)
│
├── Runtime Settings
│   ├── [Input] Rust Path (optional, for auto-install)
│   └── [Select] Log Level: error, warn, info, debug, trace
│
├── Environment Variables
│   └── [Key-value editor - add/remove rows]
│
├── Allowed HTTP Routes (comma-separated)
│   └── [Input] Routes
│
├── Installation
│   ├── [Toggle] Auto-install Spin via cargo
│   └── [Toggle] Auto-detect spin.toml manifest
│
└── Status & Logs
    ├── [Button] Check Health
    └── [Button] View Logs
```

**AppServerTypeSelector**:
```
App Server Runtime
○ Granian (Python ASGI/WSGI)
● Spin (WASM)
```

**Implementation approach**:
- Use existing GranianSection as template
- Add `runtime_type` state: `"granian"` | `"spin"`
- Show GranianSection when `runtime_type == "granian"`
- Show SpinSection when `runtime_type == "spin"`

### SpinSection Component

```typescript
#[derive(Properties, PartialEq)]
pub struct SpinSectionProps {
    pub site_id: String,
}

#[function_component]
fn SpinSection(props: &SpinSectionProps) -> Html {
    let enabled = use_state(|| false);
    let app_path = use_state(|| String::new());
    let workers = use_state(|| 1u32);
    let log_level = use_state(|| "info".to_string());
    let health_status = use_state(|| "unknown".to_string());
    let logs = use_state(|| Vec::<String>::new());

    // Load initial config
    use_effect_with((), {
        let enabled = enabled.clone();
        let app_path = app_path.clone();
        // ...
        async move {
            let api = ApiService::new();
            if let Ok(spin_config) = api.get_site_spin_config(&props.site_id).await {
                enabled.set(spin_config.enabled.unwrap_or(false));
                app_path.set(spin_config.app_path.unwrap_or_default());
                // ...
            }
        }
    });

    let on_check_health = {
        let health_status = health_status.clone();
        Callback::from(move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.check_spin_health(&props.site_id).await {
                    Ok(_) => health_status.set("healthy".to_string()),
                    Err(_) => health_status.set("unhealthy".to_string()),
                }
            });
        })
    };

    let on_view_logs = {
        let logs = logs.clone();
        Callback::from(move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.get_site_spin_logs(&props.site_id).await {
                    Ok(log_lines) => logs.set(log_lines),
                    Err(_) => {},
                }
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="bg-tertiary border border-default rounded-lg p-4">
                <h3 class="text-lg font-medium text-primary mb-4">{ "Spin WASM Runtime" }</h3>

                <ToggleField
                    label="Enable Spin"
                    enabled={*enabled}
                    onchange={/* handler */}
                />

                <InputField
                    label="Manifest Path"
                    name="app_path"
                    value={(*app_path).clone()}
                    onchange={/* handler */}
                    placeholder="/var/www/spin-app/spin.toml"
                />

                <SelectField
                    label="Workers"
                    value={(*workers).to_string()}
                    options={["1", "2", "4", "8"]}
                    onchange={/* handler */}
                />

                <SelectField
                    label="Log Level"
                    value={(*log_level).clone()}
                    options={["error", "warn", "info", "debug", "trace"]}
                    onchange={/* handler */}
                />

                <div class="flex gap-4 mt-4">
                    <button
                        class="px-4 py-2 bg-primary text-white rounded hover:opacity-80"
                        onclick={on_check_health}
                    >
                        { "Check Health" }
                    </button>
                    <span class={format!("health-{}", *health_status)}>
                        { health_status.as_str() }
                    </span>
                </div>

                <div class="mt-4">
                    <button
                        class="px-4 py-2 bg-secondary text-white rounded hover:opacity-80"
                        onclick={on_view_logs}
                    >
                        { "View Logs" }
                    </button>
                    if !logs.is_empty() {
                        <pre class="mt-2 p-2 bg-tertiary rounded text-sm overflow-auto max-h-64">
                            { logs.iter().map(|l| html! { <div>{ l }</div> }).collect::<Html>() }
                        </pre>
                    }
                </div>
            </div>
        </div>
    }
}
```

### Files Summary - Part 4 (Admin UI)

| Layer | File | Change Type | Lines |
|-------|------|-------------|-------|
| Frontend Types | `admin-ui/src/types/mod.rs` | Add Spin types | ~30 |
| API Service | `admin-ui/src/services/api.rs` | Add Spin methods | ~50 |
| SiteEditor | `admin-ui/src/pages/site_editor.rs` | Add SpinSection | ~300 |

**Estimation: ~380 lines TypeScript**

---

## Complete Implementation Summary

### Part 1: Static Website Directory Listing UI
**Estimation: ~800 lines (400 Rust + 400 TypeScript)**

| Layer | File | Lines |
|-------|------|-------|
| Backend | `src/admin/handlers/sites.rs` | ~250 |
| Frontend Types | `admin-ui/src/types/mod.rs` | ~50 |
| API Service | `admin-ui/src/services/api.rs` | ~100 |
| SiteEditor | `admin-ui/src/pages/site_editor.rs` | ~400 |

### Part 2: Spin (Fermyon) WASM Runtime Support
**Estimation: ~1040 lines Rust**

| Layer | File | Lines |
|-------|------|-------|
| Config | `src/config/site/spin.rs` | ~150 |
| Config | `src/config/site/mod.rs` | ~30 |
| Config | `src/config/site/backend.rs` | ~10 |
| Runtime | `src/app_server/spin.rs` | ~700 |
| Runtime | `src/app_server/mod.rs` | ~30 |
| Router | `src/router.rs` | ~50 |
| HTTP | `src/http/server.rs` | ~40 |
| Worker | `src/worker/unified_server.rs` | ~30 |

### Part 3: WASM Component Support (Deferred)
**Estimation: ~600 lines Rust**

| Layer | File | Lines |
|-------|------|-------|
| Runtime | `src/serverless/spin_component.rs` | ~500 |
| Manager | `src/serverless/manager.rs` | ~100 |

### Part 4: Admin UI for Spin
**Estimation: ~380 lines TypeScript**

| Layer | File | Lines |
|-------|------|-------|
| Types | `admin-ui/src/types/mod.rs` | ~30 |
| API | `admin-ui/src/services/api.rs` | ~50 |
| Editor | `admin-ui/src/pages/site_editor.rs` | ~300 |

---

## Grand Total

| Part | Language | Lines |
|------|----------|-------|
| Part 1: Static UI | Rust + TypeScript | ~800 |
| Part 2: Spin Runtime | Rust | ~1040 |
| Part 3: WASM Components | Rust (deferred) | ~600 |
| Part 4: Spin Admin UI | TypeScript | ~380 |

**Total: ~2820 lines** (excluding deferred Phase 3)

---

## Key Insights from Deep Dives

1. **Granian Supervisor Pattern is Well-Established**: Spin can follow the exact same architecture for process management, health checks, and Unix socket proxying.

2. **Current WASM ABI is Incompatible with Spin Components**: The pointer-based ABI (`filter_request`, `handle_request`) cannot directly invoke Spin components which use WIT interfaces (`wasi:http/types`). A separate runtime is required.

3. **Theme System Has Duplicated Presets**: Frontend has hardcoded `get_preset_colors()` while backend defines `ThemePreset` enum. Consider fetching from backend for consistency.

4. **Directory Listing Already Uses Full Theme System**: The backend is complete - only needs UI exposure in admin UI.

5. **BackendType Routing is Extensible**: Adding Spin follows existing patterns used by Granian, PHP-FPM, and static file handling.

6. **Auto-Install via cargo is Simple**: `cargo install spin` is the primary installation method, similar to Granian's pip-based install.

---

## Implementation Order Recommendation

| Priority | Part | Item | Effort | Reason |
|----------|------|------|--------|--------|
| P0 | Part 1 | Static UI - Backend API | Medium | Foundation for other work |
| P0 | Part 1 | Static UI - Frontend | Medium | User-facing feature |
| P1 | Part 2 | Spin Config & Module | High | Core runtime |
| P1 | Part 2 | Spin Router Integration | Medium | Routing changes |
| P1 | Part 2 | Spin HTTP Handler | Medium | Request handling |
| P2 | Part 4 | Spin Admin UI | Medium | User-facing feature |
| P3 | Part 3 | WASM Components | High | Deferred - complex |

---

## Deferred Items (Phase 3)

The following are identified but deferred for future implementation:

- **SpinComponentRuntime**: Full component-model runtime for Spin HTTP components
- **WIT-compatible linker**: WASI HTTP preview2 linking
- **Spin SDK host functions**: KV store, outbound HTTP, AI bindings
- **Component registry**: Upload/manage Spin components via admin API

---

## Verification Commands

```bash
# Build and test
cargo test --lib --no-run
cargo test --lib <test_name>
cargo test --test integration_test

# Lint and format
cargo fmt
cargo clippy -- -D warnings

# Specific feature tests
cargo test --test integration_test -- static
cargo test --test integration_test -- spin
cargo test --lib serverless
```

---

## Notes

1. **Spin vs Granian Mutually Exclusive**: Per user clarification, Spin and Granian are separate runtime options - sites choose one or the other, not both simultaneously.

2. **cargo install for Spin**: Auto-install uses `cargo install spin` rather than downloading pre-built binaries.

3. **Theme Duplication**: The frontend currently duplicates preset colors from backend. Consider adding `/api/theme/presets` endpoint to fetch actual color values.

4. **Preview Generation**: Directory listing preview uses client-side `generate_directory_listing_preview()` similar to `generate_error_page_preview()`. Hardcoded presets match backend values but could be fetched.

---

*Plan created: 2026-04-27*
*Review status: PENDING - awaiting implementation authorization*