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

- **Guest-provided allocation**: Plugins may export `guest_alloc(size) -> ptr` to request memory from the host
- **Host-provided fallback**: If `guest_alloc` is not exported, the host uses offset `1024` (1KB reserved area)
- **Maximum data size**: 1MB (1,048,576 bytes) per single data transfer
- **Memory growth**: Plugins can grow memory up to `max_memory_mb` limit

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
  (param $status_code i32)   ;; HTTP status code
  (param $body_ptr i32)      ;; Response body pointer
  (param $body_len i32)      ;; Response body length
  (param $out_ptr i32)       ;; Output buffer pointer
  (param $out_max i32)       ;; Output buffer max size
  (result i32))              ;; New body length, or -1 on error
```

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
  (param $status_code i32)
  (param $body_ptr i32) (param $body_len i32)
  (param $out_ptr i32) (param $out_max i32)
  (result i32)
  
  ;; Add security header to all responses
  local.get $out_ptr
  i32.const 0
  i32.const 18
  memory.fill  ;; Clear output buffer
  
  ;; Write "Strict-Transport-Security: max-age=31536000"
  ;; ... (implementation details)
  
  i32.const 18  ;; Return header length
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

**Note**: Optional. If not exported, the host cannot reclaim memory.

## Host Functions (env namespace)

These functions are provided by the host and callable from the guest:

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

| Limit | Default | Description |
|-------|---------|-------------|
| `max_memory_mb` | 64 MB | Maximum linear memory size |
| `max_cpu_fuel` | 1,000,000 | CPU fuel units (0 = unlimited) |
| `timeout_seconds` | 30 | Request processing timeout |
| `max_instances` | 1 | Maximum concurrent instances per plugin |

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

- Return codes < -1 indicate fatal errors; the plugin is disabled
- Plugin errors can be configured to fail-open or fail-closed per-site

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
cargo build --target wasm32-wasi
```

## Debugging

Enable WASM plugin debugging:

```toml
[logging]
level = "debug"  # Shows filter decisions, memory operations
```

Metrics available:
- `synvoid_wasm_invocations_total` - Total plugin calls
- `synvoid_wasm_decisions_total{decision="pass|block|challenge"}` - Decision counts
- `synvoid_wasm_errors_total` - Error counts
- `synvoid_wasm_duration_seconds` - Execution time histogram
- `synvoid_wasm_fuel_consumed_total` - Fuel usage

## Version History

| Version | Changes |
|---------|---------|
| 1.0 | Initial stable ABI with filter_request, transform_response, handle_request |
| 1.1 | Added mesh host functions: mesh_query_dht, mesh_check_threat, mesh_emit_event |
