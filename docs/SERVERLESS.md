# Serverless Functions

SynVoid supports serverless function execution via WebAssembly (WASM), allowing custom request handlers to be deployed as portable, sandboxed WASM modules.

## Overview

Serverless functions provide a way to run custom logic at the WAF layer without native compilation. Functions are loaded from `.wasm` files and execute in a WASM runtime (wasmtime) with resource limits.

**Key Features:**
- WASM-based sandboxed execution via wasmtime
- Instance pooling with auto-scaling
- Per-function resource limits (memory, CPU fuel, timeout)
- Request/response handling via ABI functions

## Supported Backends

### WASM (wasmtime)

Primary serverless backend using WebAssembly:

```toml
[serverless]
enabled = true
default_memory_mb = 64
default_cpu_fuel = 1000000
default_timeout_seconds = 30
```

### Python (Granian)

Python applications run via [Granian](https://github.com/emselu/granian), a high-performance ASGI/WSGI server:

```toml
[site.app_server]
enabled = true
backend = "granian"
app_path = "/opt/app/main:app"
workers = 4
```

See [CONFIGURATION.md](./CONFIGURATION.md) for full Granian configuration options.

### PHP-FPM

PHP applications run via PHP-FPM:

```toml
[site.php]
enabled = true
root = "/var/www/html"
pool_size = 4
```

### FastCGI

Generic FastCGI backend support:

```toml
[site.fastcgi]
enabled = true
host = "127.0.0.1"
port = 9000
```

---

## WASM Serverless Configuration

### Enable Serverless

```toml
[serverless]
enabled = true
default_memory_mb = 64
default_cpu_fuel = 1000000
default_timeout_seconds = 30

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
| `default_memory_mb` | `64` | Default max memory per function |
| `default_cpu_fuel` | `1000000` | Default CPU fuel units (0 = unlimited) |
| `default_timeout_seconds` | `30` | Default max execution time |
| `functions` | `[]` | List of function definitions |

### Function Definition

| Option | Default | Description |
|--------|---------|-------------|
| `name` | - | Unique function name |
| `path` | - | Path to `.wasm` file |
| `handler` | `"handle_request"` | Exported function to call |
| `memory_mb` | `64` | Max memory for the function |
| `cpu_fuel` | `1000000` | CPU fuel units (0 = unlimited) |
| `timeout_seconds` | `30` | Max execution time |
| `env` | `{}` | Environment variables (supports `${ENV_VAR}` syntax) |

---

## WASM ABI Specification

Your WASM module must implement the following interface:

### Request Handling

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

**Parameters:**
- `method_ptr`: Pointer to method string (e.g., "GET", "POST")
- `method_len`: Length of method string
- `uri_ptr`: Pointer to URI string
- `uri_len`: Length of URI string
- `headers_ptr`: Pointer to headers JSON string
- `headers_len`: Length of headers string
- `body_ptr`: Pointer to body bytes
- `body_len`: Length of body bytes

**Returns:** `0` = success, negative = error

### Response Retrieval

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

### Memory Model

- WASM memory is linear with a maximum of `memory_mb` pages (64KB each)
- Input data (method, URI, headers, body) is copied into WASM memory
- Response data must be written to WASM memory before returning
- Return value: `0` = success, negative = error

### Headers Format

Headers are passed as a JSON string:
```json
{"Content-Type": ["application/json"], "X-Custom": ["value"]}
```

### Example WASM Module (Rust)

```rust
use wasm_bindgen::prelude::*;

static mut RESPONSE_BODY: Vec<u8> = Vec::new();
static mut RESPONSE_STATUS: i32 = 200;
static mut RESPONSE_HEADERS: Vec<u8> = Vec::new();

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
            RESPONSE_HEADERS = b"Content-Type: text/plain".to_vec();
        }
        return 0;
    }

    unsafe {
        RESPONSE_BODY = b"Not Found".to_vec();
        RESPONSE_STATUS = 404;
        RESPONSE_HEADERS = b"Content-Type: text/plain".to_vec();
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

#[no_mangle]
pub extern "C" fn get_response_headers_ptr() -> *mut u8 {
    unsafe { RESPONSE_HEADERS.as_mut_ptr() }
}

#[no_mangle]
pub extern "C" fn get_response_headers_len() -> i32 {
    unsafe { RESPONSE_HEADERS.len() as i32 }
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
cp target/wasm32-wasi/release/my_function.wasm /path/to/functions/
```

---

## Admin API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/serverless/health` | GET | Get serverless functions health status |
| `/api/serverless/functions` | GET | List all serverless functions |
| `/api/serverless/functions/{name}/stats` | GET | Get function statistics |

### Get Serverless Health

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/serverless/health
```

**Response:**
```json
{
  "enabled": true,
  "total_functions": 2,
  "total_invocations": 15420,
  "total_errors": 3,
  "healthy_functions": 2,
  "unhealthy_functions": 0
}
```

### List Functions

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/serverless/functions
```

**Response:**
```json
{
  "functions": [
    {
      "name": "auth-handler",
      "description": "JWT authentication",
      "route_count": 1,
      "allowed_methods": ["GET", "POST"],
      "memory_mb": 64,
      "timeout_seconds": 30,
      "registered_at": 3600,
      "last_invoked": 120,
      "invocation_count": 12000,
      "error_count": 2
    }
  ],
  "total_functions": 1
}
```

### Get Function Stats

```bash
curl -H "Authorization: Bearer your-admin-token" \
  http://127.0.0.1:8081/api/serverless/functions/auth-handler/stats
```

**Response:**
```json
{
  "name": "auth-handler",
  "stats": {
    "invocation_count": 12000,
    "error_count": 2,
    "avg_errors_per_invocation": 0.0002
  }
}
```

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

### Prometheus Metrics

```
# Instance counts
synvoid_serverless_instances_total{function="auth-handler"}
synvoid_serverless_instances_idle{function="auth-handler"}
synvoid_serverless_instances_active{function="auth-handler"}

# Request metrics
synvoid_serverless_requests_total{function="auth-handler"}
synvoid_serverless_duration_ms{function="auth-handler"}
```

---

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Serverless and app server configuration
- [DEVELOPER.md](./DEVELOPER.md) - WASM development guide
