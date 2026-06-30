# Plugin Milestone 2 Phase 5: Request and Response Serialization Semantics

## Goal

Make the WASM plugin ABI's request and response representation explicit, bounded, lossless where required, and safe under adversarial HTTP metadata. A plugin must evaluate the same request/response semantics that Synvoid will enforce, not a truncated or ambiguous encoding.

Milestone 1 hardened authority, signed loading, invocation state, and guest memory transfer. This phase hardens the data contract that crosses that boundary.

## Problem Statement

The current runtime has improved header serialization and guest memory safety, but serialization semantics need a dedicated production pass. The key risks are:

1. Plugins may receive a representation that is technically bounded but semantically lossy.
2. Header count, header length, URI length, body length, and response transform output need one shared policy surface rather than scattered checks.
3. HTTP/1, HTTP/2, and HTTP/3 metadata semantics can differ, especially around pseudo-headers, authority, repeated headers, casing, and invalid bytes.
4. Response transforms need clear maximum output size, status validation, and fail-open/fail-closed policy.
5. Tests should prove plugins cannot make decisions over silently corrupted metadata.

## Design Principles

1. Reject rather than truncate security-relevant request metadata.
2. Preserve raw bytes where HTTP allows non-UTF8 header values.
3. Normalize only when the normalization policy is explicit and shared with the rest of Synvoid.
4. Keep request serialization and response serialization symmetric where possible.
5. Make output limits part of the effective plugin policy, not ad hoc runtime constants.
6. Treat plugin transforms as untrusted proposals. Validate the proposed response before applying it.

## Workstream 1: Define a Versioned ABI Frame Schema

### Target

Create a documented internal frame schema for request input and response transform input/output. This does not have to become a public stable ABI immediately, but the runtime and tests should treat it as versioned.

Suggested layout for request input frame metadata:

```text
RequestFrameV1
  magic: u32
  version: u16
  flags: u16
  method_offset: u32
  method_len: u32
  uri_offset: u32
  uri_len: u32
  authority_offset: u32
  authority_len: u32
  scheme_offset: u32
  scheme_len: u32
  header_block_offset: u32
  header_block_len: u32
  body_offset: u32
  body_len: u32
  reserved...
  payload bytes...
```

The existing hook signature can remain pointer/length based for now. The host can still pass method/URI/header/body subranges to the old signature. The important part is that the runtime has one authoritative frame builder with explicit limits and tests.

### Implementation Steps

1. Add a `serialization` or `abi_frame` module under `crates/synvoid-plugin-runtime/src/`.
2. Define `RequestFramePolicy` and `ResponseFramePolicy`:

```rust
pub struct RequestFramePolicy {
    pub max_method_bytes: usize,
    pub max_uri_bytes: usize,
    pub max_authority_bytes: usize,
    pub max_header_count: usize,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,
    pub max_serialized_headers_bytes: usize,
    pub max_body_bytes: usize,
    pub max_total_frame_bytes: usize,
}

pub struct ResponseFramePolicy {
    pub max_status_code: u16,
    pub min_status_code: u16,
    pub max_header_count: usize,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,
    pub max_body_bytes: usize,
    pub max_total_frame_bytes: usize,
}
```

3. Derive default policy from `PluginLimits` / `WasmResourceLimits` rather than free constants.
4. Add one builder function for request input:

```rust
pub fn build_request_frame(
    request_parts: &http::request::Parts,
    body: &[u8],
    policy: &RequestFramePolicy,
) -> Result<RequestFrame, SerializationError>
```

5. Add one parser/validator for response transform output:

```rust
pub fn validate_response_transform_output(
    status: StatusCode,
    headers: Option<&HeaderMap>,
    body: &[u8],
    policy: &ResponseFramePolicy,
) -> Result<(), SerializationError>
```

6. Replace scattered serialization checks in `wasm_runtime.rs` with these helpers.
7. Update docs with the effective serialized fields and limits.

### Tests

Add unit tests for:

- Method over limit rejected.
- URI over limit rejected.
- Header count over limit rejected.
- Header name over limit rejected.
- Header value over limit rejected.
- Total serialized headers over limit rejected.
- Body over limit rejected before guest memory write.
- Total frame over limit rejected.
- Repeated headers preserved in deterministic order.
- Header values with non-UTF8 bytes are preserved or rejected according to explicit policy.

### Acceptance Criteria

- There is one canonical request frame builder.
- There is one canonical response output validator.
- No plugin serialization path performs lossy `as u16`/`as u32` casts without prior checked bounds.
- Tests prove oversized metadata is rejected, not truncated.

## Workstream 2: HTTP Semantics and Normalization Policy

### Target

Define exactly what plugins see for each HTTP version and how Synvoid normalizes metadata before plugin inspection.

### Required Policy Decisions

1. URI form: origin-form vs absolute-form vs authority-form.
2. Host/authority: how `Host` and HTTP/2/3 `:authority` are represented.
3. Scheme: whether plugin sees trusted scheme from listener/TLS state or request metadata.
4. Header casing: whether names are lowercased before serialization.
5. Repeated headers: preserve as repeated entries, join per RFC-compatible rules, or reject certain duplicates.
6. Hop-by-hop headers: whether plugins see them before stripping or after stripping.
7. Body: whether plugins see full body, first N bytes, streaming chunks, or no body depending on policy.

### Implementation Steps

1. Add a `PluginHttpView` type:

```rust
pub struct PluginHttpView<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub scheme: Option<&'a str>,
    pub authority: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub body_mode: PluginBodyMode,
}
```

2. Create a conversion helper from request parts to `PluginHttpView`.
3. Add a doc section describing what the plugin view includes and excludes.
4. Add tests for HTTP/1 Host and HTTP/2 authority representation where request construction allows it.
5. Add a guardrail test that forbids direct ad hoc header serialization outside the frame builder.

### Acceptance Criteria

- Plugin request view is documented.
- HTTP/1 and HTTP/2/3 authority behavior is explicit.
- Repeated header behavior is explicit and tested.
- Security-sensitive normalization is not scattered across runtime call sites.

## Workstream 3: Response Transform Output Validation

### Target

Treat response transform output from WASM as an untrusted proposal. Validate status code, headers, body length, and mutation policy before applying it.

### Implementation Steps

1. Define `PluginResponseMutationPolicy`:

```rust
pub struct PluginResponseMutationPolicy {
    pub allow_status_change: bool,
    pub allow_header_add: bool,
    pub allow_header_remove: bool,
    pub allow_body_replace: bool,
    pub allowed_header_prefixes: Vec<String>,
    pub denied_header_names: Vec<String>,
}
```

2. Add defaults:

- Response-inspect-only plugin: cannot mutate.
- Response-mutate plugin: can mutate body and safe headers within limits.
- Security headers such as `set-cookie`, `content-length`, `transfer-encoding`, and connection-specific headers should be denied unless explicit policy allows them.

3. Validate transform output before applying:

- Status must be a valid `StatusCode`.
- Header names must be valid HTTP header names.
- Header values must be valid according to the HTTP library or raw policy.
- Body length must be within `max_output_bytes`.
- If body changes, update/remove `content-length` consistently.
- Disallow hop-by-hop headers in transformed output unless explicit policy allows.

4. Add logging/metrics for rejected transform proposals.
5. Apply fail-open/fail-closed policy consistently:

- Default response transform rejection should fail open by preserving the original response.
- Security-sensitive transform policies may opt into fail closed.

### Tests

Add tests for:

- Invalid status code rejected.
- Overlarge transformed body rejected.
- Attempt to mutate headers without `ResponseMutate` rejected.
- Attempt to change status without status-change permission rejected.
- Dangerous header mutation rejected by default.
- Transform failure preserves original response under fail-open policy.
- Transform failure blocks or errors under fail-closed policy.

### Acceptance Criteria

- Response transform output is validated before application.
- Transform mutation authority is capability/policy-driven.
- Fail-open/fail-closed behavior is deterministic and tested.

## Workstream 4: Metrics and Audit for Serialization Decisions

### Target

Expose why plugin serialization rejected an input or output without logging sensitive payload data.

### Implementation Steps

1. Add serialization error classes:

```rust
pub enum SerializationFailureClass {
    MethodTooLarge,
    UriTooLarge,
    HeaderCountTooLarge,
    HeaderNameTooLarge,
    HeaderValueTooLarge,
    HeaderBlockTooLarge,
    BodyTooLarge,
    FrameTooLarge,
    InvalidStatus,
    InvalidHeaderName,
    InvalidHeaderValue,
    MutationDenied,
}
```

2. Add metrics labels with bounded cardinality:

- plugin name
- hook type
- failure class
- trust tier

Avoid raw header names/values unless allowlisted and cardinality-bounded.

3. Add structured debug logs with sizes and class, not payload.
4. Update security observability guard tests if applicable.

### Tests

- Serialization rejection increments bounded metric labels.
- Logs/metrics do not include raw header values or body snippets.
- Failure class is stable for each rejection case.

## Required Validation Commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
```

Add new tests for this phase to the CI guard suite if they are separate integration tests.

## Completion Definition

This phase is complete when:

- Request serialization has one canonical frame builder and policy.
- Response transform output has one canonical validator and mutation policy.
- Oversized or invalid metadata is rejected, never silently truncated.
- HTTP view semantics are documented and tested.
- Serialization failures produce bounded metrics/audit signals.
- Existing Milestone 1 guardrails remain green.
