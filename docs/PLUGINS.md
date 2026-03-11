# Plugins

MaluWAF supports two plugin systems for extending functionality:

1. **WASM Plugins** - Sandboxed WebAssembly modules for request filtering and response transformation
2. **Native Axum Plugins** - Shared library plugins that extend routing capabilities

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      MaluWAF                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Plugin Runtime                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────┐    │   │
│  │  │WASM     │  │WASM     │  │   Axum      │    │   │
│  │  │Plugin 1 │  │Plugin 2 │  │   Plugin    │    │   │
│  │  │(Sandbox)│  │(Sandbox)│  │ (Native)    │    │   │
│  │  └─────────┘  └─────────┘  └─────────────┘    │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## WASM Plugins

WebAssembly plugins run in a sandboxed environment for safe execution of custom logic.

## Configuration

### Enable Plugins

```toml
[plugins]
enabled = true
plugins_dir = "/etc/maluwafwaf/plugins"
watch_for_changes = true

# Resource limits
[plugins.limits]
max_memory_mb = 128
max_cpu_percent = 50
max_execution_time_ms = 1000
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable plugin system |
| `plugins_dir` | `"./plugins"` | Directory containing WASM plugins |
| `watch_for_changes` | `false` | Auto-reload on file changes |

### Resource Limits

| Option | Default | Description |
|--------|---------|-------------|
| `max_memory_mb` | `128` | Max memory per plugin |
| `max_cpu_percent` | `50` | Max CPU percentage |
| `max_execution_time_ms` | `1000` | Max execution time |

## Writing a Plugin

### Rust Implementation

```rust
use wasmtime::*;

pub struct MyPlugin {
    store: Store<()>,
    filter: Func,
}

impl MyPlugin {
    pub fn new() -> Result<Self> {
        let mut engine = Engine::default();
        let mut store = Store::new(&engine, ());
        
        // Load WASM module
        let module = Module::from_file(&engine, "my_plugin.wasm")?;
        
        // Get filter function
        let filter = module.get_export(&mut store, "filter_request")
            .and_then(|e| e.into_func())
            .ok_or("filter_request not found")?;
        
        Ok(Self { store, filter })
    }
    
    pub fn filter(&mut self, request: &[u8]) -> Result<FilterResult> {
        // Call WASM function
        // Return: Pass, Block, or Challenge
    }
}
```

### WASM Interface

Your WASM module must export:

```rust
// Required: Filter incoming requests
// Returns: 0 = Pass, 1 = Block, 2 = Challenge
export fn filter_request(method: i32, uri: *const u8, uri_len: i32) -> i32;

// Optional: Transform response
// Returns: 0 = Pass, 1 = Modified
export fn transform_response(status_code: i32, body: *const u8, body_len: i32) -> i32;
```

### Example WASM (Rust)

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn filter_request(method: i32, uri: ptr, uri_len: i32) -> i32 {
    // 0 = Pass, 1 = Block, 2 = Challenge
    
    // Read URI from WASM memory
    let uri = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(uri, uri_len as usize))
            .unwrap_or("")
    };
    
    // Custom blocking logic
    if uri.contains("/admin") && method != 0 {
        return 1; // Block
    }
    
    0 // Pass
}
```

### Build Plugin

```toml
# plugin/Cargo.toml
[package]
name = "my-waf-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
```

```bash
cd plugin
cargo build --release --target wasm32-wasi
cp target/wasm32-wasi/release/my_waf_plugin.wasm /etc/maluwafwaf/plugins/
```

## Plugin API

### Request Filter

```rust
pub enum WasmFilterResult {
    Pass,                      // Allow request through
    Block(StatusCode, String), // Block with status code
    Challenge(String),         // Return challenge (e.g., CAPTCHA)
}
```

### Response Transformer

```rust
pub fn transform_response(
    &self,
    response: Response<Bytes>
) -> Result<Response<Bytes>, WasmPluginError>;
```

## Built-in Plugin Examples

### Rate Limiting Plugin

```toml
# plugins/rate_limit.wasm
# Custom rate limiting with different rules
```

### Auth Plugin

```toml
# plugins/jwt_auth.wasm
# JWT token validation
```

### WAF Plugin

```toml
# plugins/custom_rules.wasm
# Custom detection rules
```

## Loading Plugins

### Automatic Loading

Place `.wasm` files in plugins directory:

```
/etc/maluwafwaf/plugins/
├── my_plugin.wasm
├── auth_plugin.wasm
└── rate_limit.wasm
```

### Per-Site Plugins

```toml
# config/sites/example.com.toml
[site.plugins]
enabled = true

[site.plugins.load]
- "auth_plugin.wasm"
- "rate_limit.wasm"
```

### Plugin Order

Plugins execute in order defined in config:

```toml
[site.plugins.load]
- "ip_check.wasm"     # Runs first
- "auth.wasm"         # Runs second
- "rate_limit.wasm"   # Runs third
```

## Security

### Sandbox

WASM plugins run in a sandboxed environment:

- No filesystem access (except configured paths)
- No network access
- Memory limits enforced
- Execution timeout enforced

### Signed Plugins

Verify plugin integrity:

```toml
[plugins]
require_signed = true
signing_key_path = "/etc/maluwafwaf/keys/plugin.key"
```

## Troubleshooting

### Plugin Not Loading

```bash
# Check plugin file
ls -la /etc/maluwafwaf/plugins/

# Validate WASM
wasm-validate /etc/maluwafwaf/plugins/my_plugin.wasm
```

### Execution Timeout

Increase timeout in config:

```toml
[plugins.limits]
max_execution_time_ms = 5000
```

### Memory Issues

Reduce memory limit:

```toml
[plugins.limits]
max_memory_mb = 64
```

## Metrics

```bash
maluwaf_plugin_load_total       # Plugins loaded
maluwaf_plugin_execution_total  # Total executions
maluwaf_plugin_block_total      # Blocks by plugins
maluwaf_plugin_error_total     # Plugin errors
maluwaf_plugin_duration_ms      # Execution duration
```

## Best Practices

1. **Minimal Plugins** - Keep logic simple
2. **Fail Open** - Default to pass on errors
3. **Log Everything** - Add detailed logging
4. **Test Thoroughly** - Unit test WASM code
5. **Version Control** - Track plugin versions
6. **Monitor Performance** - Watch execution time

---

## Native Axum Plugins

Native plugins are shared libraries that extend MaluWAF's routing capabilities using the Axum web framework. They offer better performance than WASM but require more careful security considerations.

### Supported Formats

| Platform | Extension |
|----------|-----------|
| Linux | `.so` |
| macOS | `.dylib` |
| Windows | `.dll` |

### Required Exports

Your plugin must export:

```rust
use axum::{Router, routing::get};

// ABI version symbol (required for compatibility check)
#[no_mangle]
pub static maluwaf_abi_version: *const std::ffi::c_char = 
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::ffi::c_char;

// Factory function that creates the router
#[no_mangle]
pub extern "C" fn create_router() -> *mut Router<()> {
    let router = Router::new()
        .route("/", get(|| async { "Hello from plugin!" }))
        .route("/api/custom", get(my_handler));
    Box::into_raw(Box::new(router))
}

async fn my_handler() -> &'static str {
    "Custom endpoint from native plugin"
}
```

### Building a Native Plugin

```toml
# Cargo.toml
[package]
name = "my-maluwaf-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
axum = "0.8"
```

```bash
# Build for Linux
cargo build --release --target x86_64-unknown-linux-gnu

# Build for macOS
cargo build --release --target x86_64-apple-darwin

# Output: target/release/libmy_maluwaf_plugin.so (or .dylib)
```

### Configuration

```toml
[plugins.axum]
enabled = true

[[plugins.axum.plugins]]
name = "my-plugin"
path = "/etc/maluwaf/plugins/my_plugin.so"
```

### Security Validations

MaluWAF performs the following security checks when loading native plugins:

1. **Symlink Prevention** - Rejects plugin files that are symlinks
2. **Permission Check** - Warns if permissions are not 755 or 500 (Unix)
3. **Extension Validation** - Only accepts proper shared library extensions
4. **ABI Version Check** - Validates `maluwaf_abi_version` symbol exists

### Security Considerations

> **Warning:** Native plugins run in the same process as MaluWAF and have full access to system resources. Only load plugins from trusted sources.

- Native plugins are **not sandboxed**
- They can access files, network, and system calls
- A crashing plugin can crash the entire WAF
- Memory corruption in a plugin affects the host process

### Best Practices for Native Plugins

1. **Trust Verification** - Only load plugins from verified sources
2. **Minimal Permissions** - Set file permissions to 755 or 500
3. **Code Review** - Audit plugin source code before deployment
4. **Isolation** - Consider running critical services in separate processes
5. **Monitoring** - Watch for crashes and memory leaks
6. **Version Pinning** - Lock plugin versions in production

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Plugin configuration
- [DEVELOPER.md](./DEVELOPER.md) - Plugin development guide
- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Custom attack detection plugins
