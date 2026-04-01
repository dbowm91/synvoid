# Serverless Functions

MaluWAF supports serverless function execution via WebAssembly, allowing custom request handlers to be deployed as portable, sandboxed WASM modules.

## Overview

Serverless functions provide a way to run custom logic at the WAF layer without native compilation. Functions are loaded from `.wasm` files in the `plugins/` directory and execute in a WASM runtime with resource limits.

**Key Features:**
- WASM-based sandboxed execution
- Instance pooling with auto-scaling
- Per-function resource limits (memory, CPU fuel, timeout)
- Request/response handling via `handle_request` ABI

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      MaluWAF                             │
│  ┌─────────────────────────────────────────────────┐   │
│  │           Serverless Manager                     │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │           Instance Pool                  │   │   │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  │   │   │
│  │  │  │Instance │  │Instance │  │Instance │  │   │   │
│  │  │  │   1     │  │   2     │  │   N     │  │   │   │
│  │  │  │(WASM)   │  │(WASM)   │  │(WASM)   │  │   │   │
│  │  │  └─────────┘  └─────────┘  └─────────┘  │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Configuration

### Enable Serverless

```toml
[serverless]
enabled = true

[[serverless.functions]]
name = "auth-handler"
path = "/functions/auth.wasm"
handler = "handle_request"
memory_mb = 64
cpu_fuel = 1000000
timeout_seconds = 30

[serverless.functions.env]
REDIS_URL = "redis://localhost:6379"
API_KEY = "${ENV_API_KEY}"

[[serverless.functions]]
name = "transform-request"
path = "/functions/transform.wasm"
memory_mb = 32
timeout_seconds = 10
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable serverless function execution |
| `functions` | `[]` | List of function definitions |

### Function Definition

| Option | Default | Description |
|--------|---------|-------------|
| `name` | - | Unique function name |
| `path` | - | Path to `.wasm` file in `plugins/` directory |
| `handler` | `"handle_request"` | Exported function to call |
| `memory_mb` | `64` | Max memory for the function |
| `cpu_fuel` | `1000000` | CPU fuel units (0 = unlimited) |
| `timeout_seconds` | `30` | Max execution time |
| `env` | `{}` | Environment variables (supports `${ENV_VAR}` syntax) |

---

## Writing WASM Functions

### Required ABI

Your WASM module must export:

```rust
#[no_mangle]
pub extern "C" fn handle_request(
    method_ptr: *const u8,
    method_len: i32,
    uri_ptr: *const u8,
    uri_len: i32,
    headers_ptr: *const u8,
    headers_len: i32,
    body_ptr: *const u8,
    body_len: i32,
) -> i32;
```

### Memory Model

- WASM memory is linear with a maximum of `memory_mb` pages (64KB each)
- Input data (method, URI, headers, body) is copied into WASM memory
- Return value: `0` = success, negative = error

### Response Format

Functions write response via exported memory:

```rust
#[no_mangle]
pub extern "C" fn get_response_body_ptr() -> *mut u8;

#[no_mangle]
pub extern "C" fn get_response_body_len() -> i32;

#[no_mangle]
pub extern "C" fn get_response_status() -> i32;

#[no_mangle]
pub extern "C" fn get_response_headers_ptr() -> *mut u8;

#[no_mangle]
pub extern "C" fn get_response_headers_len() -> i32;
```

### Example WASM (Rust)

```rust
use wasm_bindgen::prelude::*;

static mut RESPONSE_BODY: Vec<u8> = Vec::new();
static mut RESPONSE_STATUS: i32 = 200;

#[wasm_bindgen]
pub fn handle_request(
    method_ptr: *const u8,
    method_len: i32,
    uri_ptr: *const u8,
    uri_len: i32,
    _headers_ptr: *const u8,
    _headers_len: i32,
    _body_ptr: *const u8,
    _body_len: i32,
) -> i32 {
    let method = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(method_ptr, method_len as usize))
            .unwrap_or("")
    };
    
    let uri = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(uri_ptr, uri_len as usize))
            .unwrap_or("")
    };
    
    if method == "GET" && uri == "/api/hello" {
        unsafe {
            RESPONSE_BODY = b"Hello, World!".to_vec();
            RESPONSE_STATUS = 200;
        }
        return 0;
    }
    
    unsafe {
        RESPONSE_BODY = b"Not Found".to_vec();
        RESPONSE_STATUS = 404;
    }
    0
}

#[no_mangle]
pub extern "C" fn get_response_body_ptr() -> *mut u8 {
    unsafe { RESPONSE_BODY.as_mut_ptr() }
}

#[no_mangle]
pub extern "C" fn get_response_body_len() -> i32 {
    unsafe { RESPONSE_BODY.len() as i32 }
}

#[no_mangle]
pub extern "C" fn get_response_status() -> i32 {
    unsafe { RESPONSE_STATUS }
}
```

### Build Function

```toml
# function/Cargo.toml
[package]
name = "my-serverless-function"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

```bash
cd function
cargo build --release --target wasm32-wasi
cp target/wasm32-wasi/release/my_function.wasm plugins/
```

---

## Instance Pooling

The instance pool manages pre-warmed WASM instances for each function.

### Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `min_instances` | `1` | Minimum instances to keep warm |
| `max_instances` | `10` | Maximum instances per function |
| `idle_timeout_seconds` | `300` | Idle time before eviction |
| `scale_up_threshold` | `0.7` | Utilization % to trigger scale up |
| `scale_down_threshold` | `0.3` | Utilization % to trigger scale down |
| `scale_up_cooldown_seconds` | `30` | Cooldown between scale up events |
| `scale_down_cooldown_seconds` | `60` | Cooldown between scale down events |
| `pre_warm_instances` | `2` | Instances to create at startup |

### Auto-Scaling

The pool runs an autoscaler that:
1. Checks utilization every 10 seconds
2. Scales up when active instances exceed `scale_up_threshold`
3. Scales down when active instances fall below `scale_down_threshold`
4. Evicts idle instances after `idle_timeout_seconds`

### Instance States

| State | Description |
|-------|-------------|
| `Initializing` | Being created/compiled |
| `Ready` | Idle and available |
| `Busy` | Handling a request |
| `Evicted` | Removed from pool |

---

## Metrics and Monitoring

### Pool Metrics

| Metric | Description |
|--------|-------------|
| `total_instances` | Total instances in pool |
| `idle_instances` | Idle and available |
| `active_instances` | Currently processing |
| `total_requests` | Requests handled |
| `total_duration_ms` | Cumulative execution time |
| `utilization` | Active / Total ratio |

### Accessing Metrics

```rust
use maluwaf::serverless::instance_pool::ServerlessManager;

let manager = ServerlessManager::new(config);
let metrics = manager.get_all_metrics();

for (name, pool_metrics) in metrics {
    println!("{}: {} active, {:.1}% util", 
        name, 
        pool_metrics.active_instances,
        pool_metrics.utilization * 100.0
    );
}
```

### Prometheus Metrics

```
# Instance counts
maluwaf_serverless_instances_total{function="auth-handler"}
maluwaf_serverless_instances_idle{function="auth-handler"}
maluwaf_serverless_instances_active{function="auth-handler"}

# Request metrics
maluwaf_serverless_requests_total{function="auth-handler"}
maluwaf_serverless_duration_ms{function="auth-handler"}
```

---

## Limitations

This is a **stub implementation**. The following are known limitations:

1. **No Deno Runtime** - The Deno/V8 isolate pool is not yet implemented (feature gate `deno`)
2. **Single-Threaded WASM** - WASM instances execute sequentially per pool
3. **No Cold Start Optimization** - Instance creation has no caching of compiled modules
4. **No Streaming Support** - Request/response bodies must fit in memory
5. **No Concurrency Limits** - Per-function concurrent request limits not enforced
6. **Basic Auto-Scaling** - Scale decisions are simple threshold-based, no predictive scaling
7. **No Distributed Execution** - Functions cannot span multiple workers

---

## See Also

- [PLUGINS.md](./PLUGINS.md) - WASM plugin system (similar runtime)
- [CONFIGURATION.md](./CONFIGURATION.md) - Serverless configuration reference
- [DEVELOPER.md](./DEVELOPER.md) - WASM development guide
