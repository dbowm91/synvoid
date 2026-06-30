# Plugin Milestone 1 Phase 4: ABI Memory Boundary Hardening

## Goal

Make the host/guest WASM ABI memory boundary deterministic, non-overlapping, bounds-checked, and safe against malformed guest pointers. This phase removes the fixed-offset fallback hazard and ensures plugins inspect the request data Synvoid intended to provide.

## Problem Statement

The current pointer-length ABI writes method, URI, serialized headers, and body into guest linear memory. If the plugin exports `guest_alloc`, host code uses it. If not, the fallback writes each buffer at offset `1024`. Multiple buffers written at the same offset alias each other, so the plugin can observe corrupted or overwritten request fields.

This is a correctness bug and a potential policy-bypass bug. A WAF plugin must not make security decisions over a request representation that differs from the actual request.

The memory boundary also needs uniform checked arithmetic, clear error codes, and tests over malformed pointer/length pairs.

## Desired Architecture

Adopt one of two acceptable approaches.

Preferred approach: require allocator exports for the current ABI.

```rust
// Required exports for pointer-length ABI.
export fn guest_alloc(size: i32) -> i32;
export fn guest_free(ptr: i32, size: i32);
```

If either export is missing, reject plugin load or reject invocation before request data is copied.

Alternative approach: implement a host-side bump allocator over guest memory for plugins without `guest_alloc`. If this is chosen, the allocator must:

- allocate non-overlapping ranges;
- align ranges consistently;
- grow memory only within limits;
- reset per invocation;
- never use a fixed offset for multiple buffers.

The preferred approach is simpler and safer for Milestone 1.

## Implementation Steps

### 1. Define ABI Version and Required Exports

Add an explicit ABI validation step after module load and before runtime admission.

For the current pointer-length ABI, require:

- `memory`
- `guest_alloc`
- `guest_free`
- at least one hook export: `filter_request`, `transform_response`, or `handle_request`

Optional future improvement: require a `synvoid_plugin_abi_version` export. For this phase, at least document and test the required exports.

Suggested helper:

```rust
fn validate_guest_abi(module: &Module) -> Result<GuestAbiInfo, WasmPluginError>
```

Where:

```rust
pub struct GuestAbiInfo {
    pub has_filter_request: bool,
    pub has_transform_response: bool,
    pub has_handle_request: bool,
    pub requires_allocator: bool,
}
```

If backwards compatibility requires pass-through plugins with no hooks, allow them only if explicitly marked as such in the manifest. Otherwise, a plugin with no hooks should fail load rather than silently doing nothing.

### 2. Remove Fixed-Offset Fallback

Change `write_to_guest_memory()` so missing `guest_alloc` is an error:

```rust
let alloc_fn = exports.guest_alloc.as_ref().ok_or_else(|| {
    WasmPluginError::LoadFailed("plugin missing required guest_alloc export".into())
})?;
```

Do not write to `1024` as a fallback. If a transitional compatibility mode is required, gate it behind a development-only config flag and mark it unsafe/deprecated.

### 3. Add Checked Pointer Arithmetic

Audit and update all memory operations:

- `write_to_guest_memory()`
- `read_from_guest_memory()`
- `get_env` host function
- `synvoid_read_body_chunk`
- `mesh_query_dht`
- `mesh_check_threat`
- `mesh_emit_event`
- response transform memory reads/writes
- handler response reads/writes

Use checked arithmetic:

```rust
fn checked_guest_range(
    ptr: i32,
    len: i32,
    mem_len: usize,
) -> Result<std::ops::Range<usize>, WasmPluginError> {
    if ptr < 0 || len < 0 {
        return Err(WasmPluginError::ExecutionFailed("negative guest pointer/length".into()));
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start.checked_add(len).ok_or_else(|| {
        WasmPluginError::ExecutionFailed("guest pointer range overflow".into())
    })?;
    if end > mem_len {
        return Err(WasmPluginError::ExecutionFailed("guest pointer range out of bounds".into()));
    }
    Ok(start..end)
}
```

For host functions that return integer ABI errors, map these to stable negative codes rather than panicking.

### 4. Validate Allocation Results

When calling `guest_alloc(size)`:

- Reject negative pointers.
- Reject zero pointer for non-empty allocation if zero is reserved by convention.
- Reject ranges outside memory.
- Grow memory only if the effective memory budget allows it.
- Reject allocation sizes greater than max input/output limits.

If `guest_alloc` traps, treat it as a plugin runtime failure and do not continue copying partial data.

### 5. Free Guest Memory Safely

`guest_free` should be called after the guest hook returns, but failures from `guest_free` should not panic. Record a metric or debug log. If `guest_free` traps, treat the instance as poisoned and do not return it to the pool.

Consider a small helper that tracks allocations:

```rust
struct GuestAllocation {
    ptr: i32,
    len: i32,
}
```

Then free all successful allocations in a cleanup section. If an intermediate write fails, clean up already-allocated ranges where possible.

### 6. Harden Header Serialization

Header serialization should reject oversized counts and values before encoding.

Current format uses `u16` fields. Enforce:

- header count <= `u16::MAX`
- header name length <= `u16::MAX`
- header value length <= `u16::MAX`
- total serialized header bytes <= manifest/effective input limit

Suggested change:

```rust
fn serialize_headers(headers: &HeaderMap) -> Result<Vec<u8>, WasmPluginError>
```

Do not cast with `as u16` until after checks pass.

### 7. Preserve Request Representation Integrity

The plugin must receive method, URI, headers, and body as independent immutable snapshots for that invocation.

Add an internal debug/test helper to expose the ranges allocated for each field in test mode. This makes it easy to assert non-overlap.

Example invariant:

```rust
assert!(ranges_are_pairwise_disjoint(&[method, uri, headers, body]));
```

## Required Tests

### Unit Tests

- `checked_guest_range()` rejects negative pointer.
- `checked_guest_range()` rejects negative length.
- `checked_guest_range()` rejects overflow.
- `checked_guest_range()` rejects out-of-bounds ranges.
- `checked_guest_range()` accepts valid range at end of memory.
- Header serialization rejects too many headers.
- Header serialization rejects oversized header names.
- Header serialization rejects oversized header values.
- Header serialization rejects total encoded size beyond input limit.

### ABI Validation Tests

- Plugin missing `memory` fails load.
- Plugin missing `guest_alloc` fails load or invocation according to chosen policy.
- Plugin missing `guest_free` fails load or invocation according to chosen policy.
- Plugin with no hooks fails load unless explicitly declared pass-through.
- Plugin with valid hooks and allocator loads.

### Runtime Fixture Tests

Use small WASM fixtures or WAT modules:

- Valid allocator plugin receives method, URI, headers, and body in distinct ranges.
- Allocator returns negative pointer: invocation fails and instance is not returned to pool.
- Allocator returns out-of-bounds pointer: invocation fails.
- Guest traps during `guest_alloc`: failure is classified as runtime failure.
- Guest traps during `guest_free`: invocation may have completed, but instance is dropped/poisoned.
- Plugin returns out-of-bounds response pointer/length: response transform fails safely.

### Regression Test for Fixed Offset

Add a guardrail test that rejects reintroduction of the fixed-offset fallback pattern in `write_to_guest_memory()`. The test can scan for `1024i32` in that function or, preferably, use a fixture plugin without allocator and assert it fails.

## Edge Cases

- Empty body may use `(0, 0)` and should not require allocation.
- Empty method/URI should still be treated consistently, although HTTP method and URI are normally non-empty.
- Header values may contain non-UTF8 bytes; serialization should preserve raw bytes.
- Guest memory can grow during calls; check ranges after growth and before every read/write.
- A malicious allocator can return overlapping ranges. Host should not trust guest allocator to avoid overlap if it asks separately for each field. If this risk is unacceptable, allocate one contiguous host-controlled guest buffer and subdivide it manually after a single `guest_alloc(total_size)` call.

## Recommended Safer Allocation Pattern

Instead of calling `guest_alloc()` separately for method, URI, headers, and body, prefer one allocation for the total input frame:

```text
[input_frame]
  method bytes
  uri bytes
  serialized headers
  body bytes
```

Then pass offsets/lengths into the guest hook. This avoids relying on guest allocator non-overlap across multiple calls. If changing the ABI is too large for this phase, keep the current multi-pointer ABI but add tests for allocator overlap behavior.

A middle-ground approach:

1. Call `guest_alloc(total_len)` once.
2. Write all request fields into non-overlapping subranges inside that allocation.
3. Pass each subrange pointer/length to the existing hook signature.
4. Call `guest_free(base_ptr, total_len)` once.

This preserves the current hook signature while avoiding allocator overlap hazards.

## Acceptance Criteria

This phase is complete when:

- The fixed-offset `1024` fallback is removed or development-only and disabled by default.
- Plugins using the current pointer-length ABI require allocator exports or use a safe host-managed allocation strategy.
- All guest pointer/length handling uses checked arithmetic.
- Header serialization rejects lossy/truncating encodings.
- Guest allocator and free failures are handled without panics.
- Poisoned/trapped instances are not returned to the pool.
- Runtime tests prove request fields are not silently aliased or overwritten.

## Non-Goals

- Redesigning the plugin ABI into WASM components. This phase hardens the existing core module ABI.
- Full docs rewrite. That belongs to the final documentation milestone.
- Native Axum plugin safety. That belongs to the operator safety milestone.
