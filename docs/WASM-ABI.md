# SynVoid WASM Guest ABI Specification

> Version: 1.0  
> Status: Stable

This document describes the Application Binary Interface (ABI) for WASM plugins running in the SynVoid guest environment.

## Overview

SynVoid supports WASM-based request filtering and response transformation plugins. Plugins run in a sandboxed WASM environment using [Wasmtime](https://github.com/bytecodealliance/wasmtime) as the runtime.

## Memory Layout

### Linear Memory Model

```
+------------------+  <- 0x0
| Reserved (1KB)   |     Used for host-guest protocol headers
+------------------+
| Plugin Data      |     Guest allocates via guest_alloc()
| ...              |
+------------------+
| Guard Page       |     Memory growth cannot exceed limit
+------------------+
| max_memory_mb    |
+------------------+
```

### Memory Allocation

- **Guest-provided allocation**: Plugins export `guest_alloc(size) -> ptr` to request memory from the host; production trust tiers require it
- **Host-provided fallback**: A 1KB reserved area at the base of guest memory is used when a module has no allocator (development tier only)
- **Maximum data size**: 1 MiB (1,048,576 bytes) per single data transfer (`MAX_WASM_DATA_SIZE`)
- **Memory growth**: Plugins can grow memory up to `max_memory_mb` (`limits.max_memory_mb * 1024 * 1024`, capped at `max_pages`)

### String Encoding

All strings (method, URI, headers) are passed as pointer/length pairs using UTF-8 encoding.

## Guest ABI Functions

### `filter_request`

```wat
(filter_request
  (param $method_ptr i32)    ;; Method string pointer
  (param $method_len i32)    ;; Method string length
  (param $uri_ptr i32)       ;; URI string pointer  
  (param $uri_len i32)       ;; URI string length
  (param $headers_ptr i32)   ;; Serialized headers pointer
  (param $headers_len i32)   ;; Serialized headers length
  (param $body_ptr i32)      ;; Request body pointer
  (param $body_len i32)      ;; Request body length
  (result i32))              ;; Return code
```

**Purpose**: Inspect a request and return a filtering decision.

**Return Codes**:
| Code | Meaning |
|------|---------|
| 0 | `Pass` - Request allowed to proceed |
| 1 | `Block` - Request blocked with 403 Forbidden |
| 2 | `Challenge` - Challenge page issued to client |
| -1 | `Error` - Plugin encountered an error |

**Example**:
```wat
(func (export "filter_request")
  (param $method_ptr i32) (param $method_len i32)
  (param $uri_ptr i32) (param $uri_len i32)
  (param $headers_ptr i32) (param $headers_len i32)
  (param $body_ptr i32) (param $body_len i32)
  (result i32)
  
  ;; Example: Block all POST requests to /admin
  local.get $method_ptr
  i32.const 4
  i32.const 4  ;; "POST" length
  call $str_eq
  if (result i32)
    local.get $uri_ptr
    i32.const 6
    call $starts_with_admin
    if
      i32.const 1  ;; Block
      return
    end
  end
  i32.const 0  ;; Pass
)
```

### `transform_response`

```wat
(transform_response
  (param $status_ptr i32)   ;; Response status code pointer (canonical frame bytes)
  (param $status_len i32)   ;; Response status length
  (param $body_ptr i32)      ;; Response body pointer
  (param $body_len i32)      ;; Response body length
  (param $out_ptr i32)       ;; Output buffer pointer
  (param $out_max i32)       ;; Output buffer max size
  (result i32))              ;; New body length, or -1 on error
```

Signature type in the runtime is `TransformResponseFn = TypedFunc<(i32, i32, i32, i32, i32), i32>` — six i32 parameters, where the first two are the **status pointer and length**, not a bare `status_code` integer (`crates/synvoid-plugin-runtime/src/wasm_runtime.rs:262`).

**Purpose**: Transform an upstream response before sending to client.

**Return Values**:
| Value | Meaning |
|-------|---------|
| > 0 | New body length (bytes written to `out_ptr`) |
| 0 | Empty body |
| -1 | Error |

**Example**:
```wat
(func (export "transform_response")
  (param $status_ptr i32) (param $status_len i32)
  (param $body_ptr i32) (param $body_len i32)
  (param $out_ptr i32) (param $out_max i32)
  (result i32)

  ;; Copy the upstream body into the output buffer, then rewrite headers
  ;; via the response frame policy (status 100-599 enforced host-side).
  ;; ... (implementation details)

  local.get $body_len  ;; Return new body length
)
```

### `handle_request` (Serverless Mode)

```wat
(handle_request
  (param $method_ptr i32)    ;; Method string pointer
  (param $method_len i32)    ;; Method string length
  (param $uri_ptr i32)       ;; URI string pointer
  (param $uri_len i32)       ;; URI string length
  (param $headers_ptr i32)   ;; Serialized headers pointer
  (param $headers_len i32)   ;; Serialized headers length
  (param $body_ptr i32)      ;; Request body pointer
  (param $body_len i32)      ;; Request body length
  (param $out_status_ptr i32);; Output: status code (4 bytes, u32 little-endian)
  (param $out_body_ptr i32)  ;; Output: response body pointer
  (param $out_body_max i32)  ;; Output: max response body size
  (result i32))              ;; Response body length, or -1 on error
```

**Purpose**: Full request handling for serverless function execution.

**Return Values**:
| Value | Meaning |
|-------|---------|
| >= 0 | Response body length |
| -1 | Error |

**Output**: The plugin writes a 4-byte little-endian status code to `out_status_ptr` and the response body to `out_body_ptr`.

### `guest_alloc`

```wat
(guest_alloc
  (param $size i32)     ;; Number of bytes to allocate
  (result i32))         ;; Pointer to allocated memory
```

**Purpose**: Allocate memory in the guest's linear memory for receiving data from the host.

**Return**: Pointer to allocated memory, or negative on error.

### `guest_free`

```wat
(guest_free
  (param $ptr i32)      ;; Pointer to free
  (param $size i32)     ;; Size of allocation
  (result))
```

**Purpose**: Free previously allocated memory.

**Note**: Required in production. `SignedSandboxed` / `LocalSandboxed` trust tiers require **both** `guest_alloc` and `guest_free`; only development tier builds accept an alloc-only module (`DevelopmentAllowMissingFree`). Every guest pointer is range-checked with `checked_guest_range` before dereference.

## Host Functions (`env` namespace)

These functions are provided by the host and callable from the guest. All are registered on the `env` namespace in `create_linker` (`crates/synvoid-plugin-runtime/src/wasm_runtime.rs:2515`).

A separate `host` namespace also exists with kebab-case names (`log`, `get-header`, `set-header`, `get-method`, `get-uri`, `get-body`, `set-body`, `set-status`, `get-env`, `check-timeout`, `mesh-query-dht`, `mesh-check-threat`, `mesh-emit-event`, `guest-alloc`, `guest-free`). Those are compatibility stubs that return fixed placeholder values; the `env` names below are the implemented surface.

### `abort`

```wat
(import "env" "abort"
  (func $abort (param $msg_ptr i32) (param $msg_len i32)))
```

Called when the guest encounters a fatal error.

### `check_timeout`

```wat
(import "env" "check_timeout"
  (func $check_timeout (result i32)))
```

**Return**: 1 if request has exceeded timeout, 0 if still within bounds.

### `get_env`

```wat
(import "env" "get_env"
  (func $get_env
    (param $key_ptr i32) (param $key_len i32)
    (param $out_ptr i32) (param $out_max i32)
    (result i32)))
```

Read an environment variable from the host.

**Parameters**:
- `key_ptr/key_len`: Environment variable name
- `out_ptr/out_max`: Output buffer for value

**Return**: Length written, or -1 if key not found.

### `mesh_query_dht`

```wat
(import "env" "mesh_query_dht"
  (func $mesh_query_dht
    (param $key_ptr i32) (param $key_len i32)
    (param $out_ptr i32) (param $out_max i32)
    (result i32)))
```

Query the distributed hash table (DHT) for a record.

**Parameters**:
- `key_ptr/key_len`: DHT key to query (e.g., "serverless_function:my_func")
- `out_ptr/out_max`: Output buffer for record value

**Return**: Bytes written to output buffer, 0 if not found, -1 on error.

**Example**:
```wat
;; Query for serverless function info
i32.const 20  ;; key_ptr (example)
i32.const 20  ;; key_len
i32.const 1024  ;; out_ptr
i32.const 4096  ;; out_max
call $mesh_query_dht
```

### `mesh_check_threat`

```wat
(import "env" "mesh_check_threat"
  (func $mesh_check_threat
    (param $ip_ptr i32) (param $ip_len i32)
    (result i32)))
```

Check if an IP address is blocked or marked as a threat in the mesh threat intelligence.

**Parameters**:
- `ip_ptr/ip_len`: IP address string (e.g., "192.168.1.1")

**Return**: 1 if IP is threatened/blocked, 0 if clean, -1 on error.

**Capability gate**: requires both `PluginCapability::Mesh` and `mesh_policy.allow_threat_check`; otherwise the call is denied, a `CapabilityDenied` host-call failure is recorded, and `ABI_ERR_CAPABILITY_DENIED` is returned. `mesh_query_dht` likewise requires `Mesh` plus a key matching `mesh_policy.dht_read_prefixes`, and `mesh_emit_event` requires `Mesh` plus a topic listed in `mesh_policy.event_emit_topics`.

**Example**:
```wat
;; Check if client IP is a known threat
i32.const 0  ;; ip_ptr (assumes IP string at start of memory)
i32.const 15  ;; "192.168.1.100".len()
call $mesh_check_threat
i32.eqz
if
  ;; IP is clean, proceed
end
```

### `synvoid_read_body_chunk`

```wat
(import "env" "synvoid_read_body_chunk"
  (func $synvoid_read_body_chunk
    (param $out_ptr i32) (param $out_max i32)
    (result i32)))
```

Read the next chunk of upstream body data. Returns bytes written, `0` at end of body, or `ABI_ERR_TIMEOUT` (-3) when `body_chunk_timeout` elapses with no data. Chunks are clamped to `max_body_chunk_bytes` (64 KiB).

### `mesh_emit_event`

```wat
(import "env" "mesh_emit_event"
  (func $mesh_emit_event
    (param $topic_ptr i32) (param $topic_len i32)
    (param $data_ptr i32) (param $data_len i32)
    (result i32)))
```

Emit an event to the mesh event system. Functions can subscribe to events via `event_subscriptions` config.

**Parameters**:
- `topic_ptr/topic_len`: Event topic name
- `data_ptr/data_len`: Event payload data

**Return**: 0 on success, -1 on error.

**Example**:
```wat
;; Emit a custom event
i32.const 256  ;; topic string location
i32.const 6     ;; "myevent".len()
i32.const 512   ;; data location
i32.const 100   ;; data length
call $mesh_emit_event
```

## Header Serialization Format

Headers are serialized into a compact binary format:

```
[header_count: u16little-endian]
[for each header:]
  [name_len: u16little-endian]
  [name: bytes]
  [value_len: u16little-endian]
  [value: bytes]
```

**Example**:
```
02 00                           ; 2 headers
04 00 68 6f 73 74              ; "host" (4 bytes)
0b 00 65 78 61 6d 70 6c 65 2e 63 6f 6d  ; "example.com" (11 bytes)
0c 00 63 6f 6e 74 65 6e 74 2d 74 79 70 65 ; "content-type" (12 bytes)
10 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e ; "application/json" (16 bytes)
```

## Resource Limits

Config-side defaults (`WasmPluginGlobalConfig`, `crates/synvoid-config/src/plugins.rs`):

| Limit | Default | Description |
|-------|---------|-------------|
| `max_memory_mb` | 64 MB | Maximum linear memory size (`limits.max_memory_mb * 1024 * 1024`) |
| `max_cpu_fuel` | 1,000,000 | Wasmtime fuel units per execution |
| `timeout_seconds` | 30 | Request processing timeout |
| `max_instances` | 1 | Maximum concurrent instances per plugin (`WasmResourceLimits::max_instances`, `.max(1)` at use) |

Per-invocation manifest limits are a separate struct, `PluginLimits` (`crates/synvoid-plugin-runtime/src/sandbox/types.rs:726`), with its own defaults: `timeout_ms` 50, `max_input_bytes` 262144, `max_output_bytes` 262144, `max_concurrency` 4, `memory_pages` and `fuel` unset.

Additional host-side bounds: `MAX_WASM_DATA_SIZE` = 1 MiB per single data transfer; `max_body_chunk_bytes` 64 KiB, `max_env_value_bytes` 4 KiB, `max_mesh_key_bytes` 1 KiB, `max_mesh_value_bytes` 64 KiB.

ABI error codes returned by host functions (`wasm_runtime.rs:245`):

| Code | Constant | Meaning |
|------|----------|---------|
| -1 | `ABI_ERR_CAPABILITY_DENIED` | Capability/sub-capability check failed |
| -2 | `ABI_ERR_INVALID_POINTER` | Pointer/length outside guest memory |
| -3 | `ABI_ERR_TIMEOUT` | Host call budget exceeded |
| -4 | `ABI_ERR_INPUT_TOO_LARGE` | Payload exceeds the bound |
| -5 | `ABI_ERR_UNAVAILABLE` | Capability present but backend unavailable |
| -6 | `ABI_ERR_INTERNAL` | Internal host error |

### Fuel Consumption

Fuel is consumed by:
- Memory operations
- Control flow
- Function calls

Each Cranelift-compiled instruction typically consumes 1 fuel unit.

## Return Code Semantics

### Decision Flow

```
Host calls filter_request()
         │
         ▼
    ┌─────────┐
    │ code == │──No──► Continue to next plugin
    │   0     │
    └────┬────┘
         │ Yes
         ▼
    ┌─────────┐
    │ code == │──Yes──► Block (403 Forbidden)
    │   1     │
    └────┬────┘
         │ No
         ▼
    ┌─────────┐
    │ code == │──Yes──► Issue Challenge
    │   2     │
    └────┬────┘
         │ No
         ▼
    ┌─────────┐
    │ code == │──Yes──► Log Error, Pass
    │  -1     │
    └─────────┘
```

### Error Handling

- `-1` from `filter_request` is treated as a plugin error. Whether that fails open or closed is a per-instance decision: `[[plugins.wasm.plugins]] on_error = "fail_closed"` selects fail-closed, and the default (`WasmOnError::FailOpen`) lets the request through (`crates/synvoid-http/src/wasm_filter_dispatch.rs:122`).
- Host functions never return a positive "error" code — they return the negative `ABI_ERR_*` constants above.
- Return codes < -1 from host calls indicate fatal host-side conditions; the plugin is not disabled by the runtime for these, the call simply fails.

## Example WASM Module

A minimal Rust plugin that blocks SQL injection:

```rust
use wasm_bindgen::prelude::*;

#[no_mangle]
pub extern "C" fn filter_request(
    _method_ptr: i32,
    _method_len: i32,
    _uri_ptr: i32,
    _uri_len: i32,
    _headers_ptr: i32,
    _headers_len: i32,
    body_ptr: i32,
    body_len: i32,
) -> i32 {
    // In real code, you would read the body from memory
    // and check for SQL injection patterns
    // For now, always pass
    0
}
```

Compiled with:
```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1
```

The WASI preview-1 target is `wasm32-wasip1` on Rust 1.98.1 (the pinned toolchain); the legacy `wasm32-wasi` target name was renamed upstream and will not resolve.

## Debugging

Enable WASM plugin debugging:

```toml
[logging]
level = "debug"  # Shows filter decisions, memory operations
```

Metrics available (see [PLUGINS.md](./PLUGINS.md#metrics) for the full labelled tables):

- `synvoid_plugin_invoke_total{plugin,capability,status}` - Total plugin calls, labelled by capability (`filter_request`, `transform_response`, `serverless`, `serverless_streaming`)
- `synvoid_plugin_capability_violation_total{capability}` - Capability check denials
- `synvoid_plugin_host_call_failure_total{plugin,host_function,failure_class}` - Host call failures (timeout, capability denied, etc.)
- `synvoid_plugin_serialization_rejection_total{plugin,hook,failure_class,trust_tier}` - ABI frame rejections
- `synvoid_plugin_pool_hit_total` / `pool_miss_total` / `pool_dropped_total` / `concurrency_limit_exceeded_total` - Instance pool behavior

There are no `synvoid_wasm_*` metrics; the plugin runtime emits `synvoid_plugin_*` names.

## Version History

| Version | Changes |
|---------|---------|
| 1.0 | Initial stable ABI with filter_request, transform_response, handle_request |
| 1.1 | Added mesh host functions: mesh_query_dht, mesh_check_threat, mesh_emit_event |
