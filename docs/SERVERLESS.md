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
# config/sites/example.com.toml — [app_server] is a top-level site section
[app_server]
enabled = true
interface = "asgi"        # Granian interface; there is no `backend` key
app_path = "/opt/app/main:app"
workers = 4
```

See [CONFIGURATION.md](./CONFIGURATION.md) for full Granian configuration options.

### PHP-FPM

PHP applications run via PHP-FPM:

```toml
# [php] is a top-level site section; there is no `enabled` or `pool_size` key.
# The backend is selected by `socket` / `host` + `port`.
[php]
socket = "/run/php-fpm.sock"
root = "/var/www/html"
index = "index.php"
```

### FastCGI

Generic FastCGI backend support (`FastCgiConfig`):

```toml
[fastcgi]
socket = "/run/php-fpm.sock"
# or host + port instead of socket
# host = "127.0.0.1"
# port = 9000
script_filename = "/var/www/index.php"
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

`FunctionDefinition` (`crates/synvoid-config/src/serverless.rs:35`) fields:

| Option | Default | Description |
|--------|---------|-------------|
| `name` | *(required)* | Unique function name |
| `path` | *(required)* | Path to `.wasm` file |
| `handler` | `"handle_request"` | Declared handler name (see note) |
| `memory_mb` | serverless `default_memory_mb` (64) | Max memory for the function |
| `cpu_fuel` | serverless `default_cpu_fuel` (1000000) | CPU fuel units |
| `timeout_seconds` | serverless `default_timeout_seconds` (30) | Max execution time |
| `env` | `{}` | Environment variables (supports `${ENV_VAR}` syntax) |
| `pre_warm_instances`, `min_instances`, `max_instances`, `idle_timeout_seconds` | `None` | Pool sizing and idle recycling |
| `routes`, `allowed_methods`, `description` | `None` / `[]` | Routing metadata |
| `event_subscriptions` | `None` | Mesh event topics the function may subscribe to |
| `allowed_callers`, `allowed_orgs`, `require_trusted_caller`, `min_tier_level` | `None` / `false` | Caller authorization |
| `public_function` | `None` | Public vs. authorized-only |
| `allowed_dht_prefixes` | `[]` | DHT read prefixes for `mesh_query_dht` |

`ServerlessConfig` also has `waf_mode` (`ServerlessWafMode::Enforce` | `Log` | `Off`, default `Enforce`).

**Note on `handler`:** the config field exists and defaults to `"handle_request"`, but the runtime resolves the guest export by name directly — `resolve_handle_request` looks up `"handle_request"` (`wasm_runtime.rs:3182`), and `src/serverless/mod.rs` never reads `FunctionDefinition::handler`. Setting it to another name will not dispatch to that export.

---

## WASM ABI Specification

Your WASM module must implement the following interface:

### Request Handling

```rust
// HandleRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>
// Eleven i32 parameters — the last three are OUTPUT pointers supplied by the host.
pub fn handle_request(
    method_ptr: i32, method_len: i32,
    uri_ptr: i32, uri_len: i32,
    headers_ptr: i32, headers_len: i32,
    body_ptr: i32, body_len: i32,
    out_status_ptr: i32,
    out_body_ptr: i32, out_body_max: i32,
) -> i32;
```

**Parameters** — all i32, in this order:
- `method_ptr` / `method_len`: method string (e.g. "GET", "POST")
- `uri_ptr` / `uri_len`: URI string
- `headers_ptr` / `headers_len`: serialized headers frame
- `body_ptr` / `body_len`: request body bytes
- `out_status_ptr`: host buffer for a 4-byte little-endian `u32` status code
- `out_body_ptr` / `out_body_max`: host buffer for the response body

**Returns:** response body length, or `-1` on error.

### Response Retrieval

The response is written through the `out_*` parameters above; there are no `get_response_body_ptr` / `get_response_status` / `get_response_headers_*` exports in the current ABI, and the runtime never looks for them.

### Memory Model

- WASM linear memory is capped at `max_memory_mb * 1024 * 1024` bytes (`max_pages = bytes / 65536`)
- Host buffers are allocated per invocation; every guest pointer range is validated with `checked_guest_range` before dereference
- Guest allocations use `guest_alloc(size) -> ptr` and must be released with `guest_free(ptr, size)` (both required for sandboxed trust tiers)

### Headers Format

Headers are serialized in the canonical binary frame format (`abi_frame::serialize_headers_canonical`), **not** JSON:

```
[header_count: u16 LE]
  [name_len: u16 LE][name bytes][value_len: u16 LE][value bytes] ...
```

### Example WASM Module (Rust)

```rust
// Guest-side allocator. Both exports are required for sandboxed trust tiers.
#[no_mangle]
pub extern "C" fn guest_alloc(size: i32) -> i32 { /* ... */ }

#[no_mangle]
pub extern "C" fn guest_free(ptr: i32, size: i32) { /* ... */ }

// Eleven i32 params; the last three are host-provided output buffers.
#[no_mangle]
pub extern "C" fn handle_request(
    method_ptr: i32, method_len: i32,
    uri_ptr: i32, uri_len: i32,
    _headers_ptr: i32, _headers_len: i32,
    _body_ptr: i32, _body_len: i32,
    out_status_ptr: i32,
    out_body_ptr: i32, out_body_max: i32,
) -> i32 {
    let read = |ptr: i32, len: i32| -> String {
        if len <= 0 || ptr <= 0 { return String::new(); }
        unsafe {
            String::from_utf8_lossy(std::slice::from_raw_parts(ptr as *const u8, len as usize))
                .into_owned()
        }
    };

    let method = read(method_ptr, method_len);
    let uri = read(uri_ptr, uri_len);

    let (status, body): (u32, &[u8]) = if method == "GET" && uri == "/api/hello" {
        (200, b"Hello, World!")
    } else {
        (404, b"Not Found")
    };

    // Status is written as a 4-byte little-endian u32.
    unsafe { std::ptr::write_unaligned(out_status_ptr as *mut u32, status); }

    let n = body.len().min(out_body_max.max(0) as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(body.as_ptr(), out_body_ptr as *mut u8, n);
    }
    n as i32
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
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/my_function.wasm /path/to/functions/
```

The WASI preview-1 target is `wasm32-wasip1` on Rust 1.98.1 (the pinned toolchain); the legacy `wasm32-wasi` target name was renamed upstream and will not resolve.

---

## Admin API Endpoints

Registered in `src/admin/routes.rs:661`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/serverless/health` | GET | Serverless functions health status |
| `/api/serverless/functions` | GET | List all serverless functions |
| `/api/serverless/functions/{name}/stats` | GET | Get function statistics |
| `/api/serverless/config` | GET / PUT | Read or replace `ServerlessConfig` |

Note `GET /api/serverless/health` reports `enabled` as "the registry is non-empty" (`enabled: !functions.is_empty()`), not as the `[serverless] enabled` flag. The `PUT /api/serverless/config` mutating endpoint returns a typed `AdminMutationResult` and emits an `AdminAuditEvent` (`AdminActor.session_id_hash` is hashed, never a raw token).

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

There are no `synvoid_serverless_*` Prometheus series. Serverless invocations are recorded through the shared plugin-runtime counters, labelled by capability:

```
synvoid_plugin_invoke_total{capability="serverless",status="invoked"}
synvoid_plugin_invoke_total{capability="serverless_streaming",status="invoked"}
```

Pool counters (`synvoid_plugin_pool_hit_total`, `pool_miss_total`, `pool_dropped_total`, `concurrency_limit_exceeded_total`) also apply, labelled per plugin.

The per-function pool fields above (`total_instances`, `idle_instances`, `active_instances`, `total_requests`, `total_duration_ms`, `utilization`) are registry-level state surfaced through the admin endpoints, not exported metric series.

---

## See Also

- [CONFIGURATION.md](./CONFIGURATION.md) - Serverless and app server configuration
- [DEVELOPER.md](./DEVELOPER.md) - WASM development guide
