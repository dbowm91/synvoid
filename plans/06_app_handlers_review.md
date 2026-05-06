# SynVoid App Handlers Architecture Review

**Review Date:** 2026-05-06  
**Reviewer:** Architecture Review Agent  
**Document Reviewed:** `architecture/app_handlers.md`

---

## 1. Verified Claims

### 1.1 Static File Handler

| Claim | Status | Evidence |
|-------|--------|----------|
| Directory Listings | ✅ VERIFIED | `src/static_files/directory.rs:780-802` - `render_directory_listing()` with themes |
| Path Normalization | ✅ VERIFIED | `src/static_files/mod.rs:338-397` - `resolve_path()` with canonicalization + traversal check |
| MIME Type Mapping | ✅ VERIFIED | `src/static_files/mod.rs:527-530` - Uses `MIME_REGISTRY` |
| gzip/brotli pre-compression | ✅ VERIFIED | `src/static_files/mod.rs:550-622` - Checks for `.gz` and `.br` files |
| On-the-fly gzip | ✅ VERIFIED | `src/static_files/mod.rs:625-655` - `gzip_on_the_fly` with `flate2` |
| Built-in Minification | ✅ VERIFIED | `src/static_files/minifier.rs` - `MinifierGenerator` with lightningcss, minify_js, minify_html |

### 1.2 FastCGI & PHP-FPM

| Claim | Status | Evidence |
|-------|--------|----------|
| Unix Socket & TCP Support | ✅ VERIFIED | `src/php/mod.rs:11-45` - `COMMON_PHP_SOCKETS` auto-detection + TCP fallback |
| Environment Management | ✅ VERIFIED | `src/php/mod.rs:139-238` - `build_fcgi_config()` sets SCRIPT_FILENAME, FCGI_ENV vars |
| Response Streaming | ✅ VERIFIED | Uses `crate::fastcgi::get_pool()` for connection pooling |

### 1.3 Python (Granian)

| Claim | Status | Evidence |
|-------|--------|----------|
| Process Management | ✅ VERIFIED | `src/app_server/granian.rs:296-308` - `GranianSupervisor` with child process management |
| Unix Socket IPC | ✅ VERIFIED | `src/app_server/granian.rs:963-975` - `socket_url()` for Unix domain sockets |
| Simplified Deployment | ✅ VERIFIED | `src/app_server/granian.rs:236-274` - Auto-detects venv and app paths |
| Auto-install Requirements | ✅ VERIFIED | `src/app_server/granian.rs:511-576` - `ensure_requirements_installed()` |

### 1.4 Serverless WASM (Edge Functions)

| Claim | Status | Evidence |
|-------|--------|----------|
| Wasmtime Integration | ✅ VERIFIED | `src/plugin/wasm_runtime.rs:11-13` - Uses `wasmtime` crate |
| Instance Pooling | ✅ VERIFIED | `src/serverless/instance_pool.rs:88-100` - `InstancePool` struct |
| Resource Isolation | ✅ VERIFIED | `src/plugin/wasm_runtime.rs:48-58` - `WasmResourceLimits` enforces CPU/memory |
| Mesh Distribution | ✅ VERIFIED | `src/serverless/manager.rs:456-500` - DHT registration for serverless functions |

### 1.5 Spin Application Support

| Claim | Status | Evidence |
|-------|--------|----------|
| Metadata Parsing | ✅ VERIFIED | `src/spin/manifest.rs` - `SpinManifest::from_file()` exists |
| Request Mapping | ⚠️ PARTIAL | SpinHttpHandler exists but NOT integrated into HTTP routing |

---

## 2. Unverified Claims / Implementation Gaps

### 2.1 Spin HTTP Routing NOT Integrated

**Claim (app_handlers.md:44-45):** "Automatically parses Spin application manifests (`spin.toml`) to determine routes and configurations" and "Maps incoming HTTP requests to specific Spin components"

**Reality:** Per `skills/spin_wasm.md:213-220`:
> **Spin apps are NOT yet integrated into the HTTP request handling pipeline.**
> - SpinRuntime is fully implemented in `src/spin/`
> - Admin API endpoints work
> - BUT: requests need to route to Spin apps based on `spin.toml` trigger configuration

**Files Affected:**
- `src/http/server.rs` - Only checks `ServerlessManager`, not Spin
- `src/spin/handler.rs` - `SpinHttpHandler` exists but unused in HTTP dispatch

### 2.2 Minification Worker Background Process

**Claim (app_handlers.md:13):** "Built-in Minification: An experimental feature that can automatically minify CSS and JavaScript on the fly using a specialized background worker"

**Reality:** The minifier is implemented but the "specialized background worker" concept is not clearly implemented. The `MinifierClient` (`src/static_files/client.rs`) communicates via IPC, but there is no dedicated static file worker process that handles minification requests independently.

---

## 3. Bug Reports

### BUG-1: InstancePool panics on missing WASM file

**Severity:** HIGH  
**Location:** `src/serverless/instance_pool.rs:176`

```rust
pub fn new(config: InstancePoolConfig, function_definition: FunctionDefinition) -> Self {
    // ...
    let runtime = crate::plugin::WasmPluginManager::new()
        .load_plugin_with_limits(
            &wasm_path,
            // ...
        )
        .expect("Failed to load serverless function");  // <-- PANIC on error
```

**Issue:** Uses `.expect()` instead of returning `Result<InstancePool, InstancePoolError>`. If the WASM file doesn't exist, the entire server crashes.

**Fix:** Return `Result<Self, InstancePoolError>` and handle missing files gracefully.

### BUG-2: Granian socket URL malformed (trailing colon)

**Severity:** MEDIUM  
**Location:** `src/app_server/granian.rs:967`

```rust
pub fn socket_url(&self) -> String {
    let socket_path = self.config.resolve_socket_path();
    #[cfg(unix)]
    {
        format!("http://unix:{}:", socket_path.display())  // <-- EXTRA COLON
    }
```

**Issue:** The URL has a trailing colon before the path component. Correct format should be `http://unix:/path/to/socket`.

**Note:** This appears in `plans/plan.md` as APP-2 marked ✅ fixed, but code still shows the bug.

### BUG-3: Granian forward_request creates new HTTP client each call

**Severity:** MEDIUM  
**Location:** `src/app_server/granian.rs:1004-1008`

```rust
pub async fn forward_request(
    &self,
    method: http::Method,
    path: &str,
    headers: &http::HeaderMap<http::HeaderValue>,
    body: Bytes,
) -> Result<http::Response<Bytes>, String> {
    // ...
    let client = crate::http_client::create_http_client_with_config(
        std::time::Duration::from_secs(30),
        10,
        std::time::Duration::from_secs(60),
    );  // <-- New client created on EVERY request
```

**Issue:** Creating an HTTP client is expensive. Should be stored in `GranianSupervisor` and reused.

### BUG-4: reload_yara_rules_if_needed is a stub

**Severity:** LOW  
**Location:** `src/static_files/file_manager.rs:271-281`

```rust
fn reload_yara_rules_if_needed(&self) -> Result<(), YaraError> {
    #[cfg(feature = "mesh")]
    {
        let _ = self;
    }
    #[cfg(not(feature = "mesh"))]
    {
        let _ = self;
    }
    Ok(())
}
```

**Issue:** This function does absolutely nothing but is called repeatedly. If YARA rule hot-reloading is intended, this is not implemented.

---

## 4. Security Concerns

### SEC-1: Granian auto-install has no transaction safety

**Severity:** HIGH  
**Location:** `src/app_server/granian.rs:464-508`

```rust
async fn ensure_granian_installed(&self, python_binary: &PathBuf) -> Result<(), String> {
    // ...
    let install_output = Command::new(python_binary)
        .args(["-m", "pip", "install", "granian"])
        .output()
        .await
        .map_err(|e| format!("Failed to run pip install: {}", e))?;
    // No verification of package integrity
```

**Issue:** Installing packages via pip with no integrity verification (e.g., hash checking) is a supply chain risk.

### SEC-2: Requirements.txt auto-install has no transaction safety

**Severity:** HIGH  
**Location:** `src/app_server/granian.rs:511-576`

Same issue as SEC-1 but for arbitrary dependencies.

### SEC-3: PHP socket auto-detection at startup

**Severity:** LOW  
**Location:** `src/php/mod.rs:11-45`

```rust
static COMMON_PHP_SOCKETS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    // ... reads /run/php directory at startup
});
```

**Issue:** Directory reading at startup could have permissions issues or race conditions. Also, reading a directory at static initialization is generally discouraged.

### SEC-4: Hidden file bypass for .htaccess

**Severity:** LOW  
**Location:** `src/static_files/mod.rs:384-394`

```rust
if self.block_hidden_files {
    for component in full_path.components() {
        let name = component.as_os_str().to_string_lossy();
        if name.starts_with('.') && name != ".htaccess" {  // <-- .htaccess bypass
            return Err(StaticError::Forbidden(...));
        }
    }
}
```

**Issue:** The `.htaccess` exception is hardcoded. This is likely for Apache compatibility but should be configurable.

---

## 5. Missing Error Handling

### ERR-1: Static file handler - unwrap_or_default on read

**Severity:** LOW  
**Location:** `src/static_files/mod.rs:110`

```rust
StaticResponseBody::Buffered(path) => {
    Bytes::from(std::fs::read(&path).unwrap_or_default())  // <-- Silently ignores errors
}
```

**Issue:** Errors are silently swallowed. Should log or return error.

### ERR-2: Static file handler - into_response unwrap

**Severity:** LOW  
**Location:** `src/static_files/mod.rs:826-827`

```rust
StaticResponseBody::Buffered(path) => {
    Bytes::from(std::fs::read(&path).unwrap_or_default())
```

Same issue as ERR-1.

### ERR-3: Minifier cache - ignores cache errors

**Severity:** LOW  
**Location:** `src/static_files/minifier.rs:447-475`

```rust
pub fn write_to_disk(
    &self,
    site_id: &str,
    path: &str,
    content: &[u8],
    _mtime: SystemTime,
) -> Result<PathBuf, MinifierError> {
    let _key = CacheKey { ... };  // <-- Key computed but never used
    // ...
    std::fs::write(&minified_path, content)?;  // Errors propagate but key unused
}
```

---

## 6. Code Improvements

### IMP-1: Use constant-time comparison for secrets

**Location:** Various

The codebase correctly uses `subtle::ConstantTimeEq` for keys/MACs per AGENTS.md guidelines. No issues found here.

### IMP-2: Async compilation handle uses mixed locking

**Location:** `src/serverless/async_compilation.rs:34-39`

```rust
pub struct AsyncCompilationHandle {
    state: Arc<RwLock<CompilationState>>,                    // tokio::sync::RwLock
    completion_sender: Arc<std::sync::Mutex<Option<oneshot::Sender<Result<(), WasmPluginError>>>>>,  // std::sync::Mutex
    completion_receiver: Arc<std::sync::Mutex<Option<oneshot::Receiver<Result<(), WasmPluginError>>>>>,  // std::sync::Mutex
}
```

**Issue:** Mixes `tokio::sync::RwLock` with `std::sync::Mutex`. While not incorrect, it's inconsistent. Consider using all async primitives.

### IMP-3: InstancePool uses blocking parking_lot in async context

**Location:** `src/serverless/instance_pool.rs:88-100`

```rust
pub struct InstancePool {
    // ...
    instances: RwLock<Vec<Arc<ServerlessInstance>>>,        // parking_lot
    active_instances: RwLock<HashMap<String, Arc<ServerlessInstance>>>,  // parking_lot
    idle_instances: RwLock<Vec<Arc<ServerlessInstance>>>,   // parking_lot
```

**Issue:** `parking_lot::RwLock` is a blocking lock. Using it in async contexts can cause issues if the async runtime needs to park while holding the lock. Consider using `tokio::sync::RwLock`.

### IMP-4: Missing tokio-tracing spans in async operations

**Location:** `src/serverless/manager.rs`

Several async operations lack proper tracing spans for observability.

---

## 7. Missing Documentation

### DOC-1: No documentation for InstancePool autoscaling behavior

**Location:** `src/serverless/instance_pool.rs:399-437`

The autoscaler runs but its behavior is not documented. Key thresholds like `scale_up_threshold: 0.7` and `scale_down_threshold: 0.3` should be documented.

### DOC-2: No documentation for archive extraction limits

**Location:** `src/static_files/file_manager.rs:66-67`

```rust
const DEFAULT_ARCHIVE_MAX_DEPTH: u32 = 3;
const DEFAULT_ARCHIVE_MAX_SIZE: u64 = 100 * 1024 * 1024;  // 100MB
```

These security limits are not documented.

### DOC-3: Spin integration gap not documented

**Location:** `skills/spin_wasm.md:213-220`

The fact that Spin apps are registered but NOT reachable via HTTP should be explicitly documented in `architecture/app_handlers.md`.

### DOC-4: WASM resource limits not documented

**Location:** `src/plugin/wasm_runtime.rs:48-58`

Default limits like `max_cpu_fuel: 1000000` and `timeout_seconds: 30` are not documented.

---

## 8. Architecture Assessment Summary

| Component | Implementation | Security | Error Handling | Documentation |
|-----------|---------------|----------|----------------|---------------|
| Static File Handler | ✅ Complete | ✅ Good | ⚠️ Some unwrap_or_default | ⚠️ Needs more |
| FastCGI/PHP-FPM | ✅ Complete | ⚠️ Socket auto-detect | ✅ Good | ⚠️ Needs more |
| Python (Granian) | ✅ Complete | ⚠️ No pip integrity | ⚠️ HTTP client reuse | ⚠️ Needs more |
| Serverless WASM | ✅ Complete | ✅ Good | ❌ InstancePool panic | ⚠️ Needs more |
| Spin Support | ⚠️ Partial | ✅ Good | ✅ Good | ❌ NOT integrated |

### Key Findings

1. **Spin HTTP integration is missing** - The most significant gap is that Spin apps can be registered but cannot receive HTTP requests.

2. **InstancePool can panic** - The `.expect()` in `instance_pool.rs:176` is a crash risk.

3. **Granian HTTP client efficiency** - Creating a new client per request is wasteful.

4. **Pip install lacks integrity checks** - Both Granian and requirements.txt auto-install should verify hashes.

5. **Documentation incomplete** - Architecture doc claims Spin routing works but it doesn't.

---

## 9. Recommendations

### High Priority

1. **Fix InstancePool panic** - Change `new()` to return `Result<Self, InstancePoolError>`
2. **Complete Spin HTTP integration** - Wire `SpinAppsManager` into HTTP server dispatch
3. **Add pip package verification** - Use hash-checking for auto-installed packages

### Medium Priority

4. **Fix Granian socket URL** - Remove trailing colon
5. **Reuse HTTP client in Granian** - Store client in `GranianSupervisor`
6. **Document Spin integration gap** - Update `app_handlers.md` to clarify current state

### Low Priority

7. **Replace parking_lot with tokio::sync** in InstancePool
8. **Add tracing spans** to async serverless operations
9. **Document archive extraction limits**
10. **Implement or remove** `reload_yara_rules_if_needed()`

---

*End of Review*
