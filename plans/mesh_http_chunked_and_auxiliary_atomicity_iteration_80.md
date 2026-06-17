# Mesh HTTP Chunked Framing and Auxiliary Atomicity — Iteration 80

## Purpose

Iteration 79 completed most of the HTTP-over-mesh proxy and auxiliary-task ownership work. The current tree at `644b153748ff0ad07198ac5d99c0c0abd164ae51` now has request metadata parsed from header bytes, fixed-length and chunked backend response framing, persistent backend support, explicit trailing-byte rejection, owned edge-replica refresh work, and module-local lifecycle tests.

The remaining defects are narrow:

1. Chunked response parsing does not consume body bytes already present in `FramedHttpResponseHead.body_prefix`.
2. Auxiliary tasks can complete and publish `AuxiliaryTaskExit` before their registry entry is inserted.
3. Auxiliary deduplication, capacity checking, stale-task teardown, and insertion are not atomic under concurrent submissions.
4. Informational HTTP responses such as `100 Continue` and `103 Early Hints` are treated as the final response.
5. Chunked wire framing can be passed through response transforms as if it were decoded entity data.
6. Close-delimited response handling is too permissive for HTTP/1.1.
7. Response header token parsing and error classification need small corrections.
8. Obsolete whole-header metadata helpers remain available and could bypass the parsed request metadata path.

This should be the final narrow mesh transport pass before moving to worker-level mesh supervision.

The key invariants are:

> Framing parsers must consume all bytes already read before requesting more bytes from the socket.

> An auxiliary completion event must never be observable before the corresponding ownership record exists.

> HTTP informational responses are intermediate; transforms operate on decoded entity bytes or are skipped.

---

## Non-Goals

Do not enable worker-level mesh supervision.

Do not redesign the proxy around Hyper unless a small internal codec is insufficient.

Do not add HTTP/2 or HTTP/3 backend support.

Do not add request pipelining, WebSocket, `CONNECT`, or bidirectional tunnel support.

Do not broaden edge-replica refresh behavior beyond ownership, deduplication, and capacity correctness.

---

# Part A — Make Chunked Parsing Prefix-Aware

## Phase 1 — Introduce A Prefix-Aware Buffered Reader

Create a small internal adapter used by chunked framing:

```rust
struct PrefixReader<R> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: R,
}
```

Implement an async read helper that consumes `prefix` first and only then reads from `inner`.

Preferred API:

```rust
impl<R: AsyncRead + Unpin> PrefixReader<R> {
    async fn read_byte_with_timeout(...)
    async fn read_exact_with_timeout(...)
    async fn read_line_crlf_with_timeout(...)
}
```

Alternative: use `tokio::io::chain(Cursor::new(prefix), reader)` if the ownership and trait bounds remain simple.

## Phase 2 — Rewrite `read_chunked_http_response_body()`

The parser must treat `body_prefix` as unread input, not merely bytes to append to the output.

Required algorithm:

1. Wrap `body_prefix` and backend reader in one prefix-aware input.
2. Read a CRLF-terminated chunk-size line.
3. Parse hexadecimal size before any `;` extension.
4. Append the original size line to raw output.
5. Read exactly the chunk payload from the unified input.
6. Read and validate the payload CRLF.
7. On size zero, read trailers through the final empty line.
8. Return the complete raw chunked wire body.

Preserve the current header/body/trailer limits and idle/total deadlines.

## Phase 3 — Bound Prefix Before Parsing

Before parsing:

- reject `body_prefix.len() > max_body_bytes + max_trailer_bytes + framing_overhead`;
- avoid duplicate allocations where practical;
- count all prefix bytes toward wire-size limits.

## Phase 4 — Add Coalesced-Prefix Tests

Use the actual chunked parser with `tokio::io::duplex()`.

Required cases:

- prefix contains complete first chunk-size line;
- prefix contains partial chunk-size line;
- prefix contains size line plus partial payload;
- prefix contains multiple complete chunks;
- prefix contains the entire chunked body including trailers;
- malformed prefix followed by valid socket bytes still fails;
- zero-size chunk split between prefix and socket;
- trailer terminator split between prefix and socket.

These tests must invoke production framing helpers.

---

# Part B — Make Auxiliary Registration Atomic

## Phase 5 — Add A Submission Serialization Primitive

Add a dedicated mutex to `MeshTransport`:

```rust
auxiliary_submission_lock: Arc<tokio::sync::Mutex<()>>,
```

Use it only around auxiliary deduplication/capacity/reservation/spawn/insert operations.

This is acceptable because auxiliary submissions are low-volume and correctness is more important than parallel submission throughput.

Clone/share it in all transport clones.

## Phase 6 — Add Registry Reservations

Represent a pending auxiliary submission before the task can run.

Suggested enum:

```rust
enum AuxiliaryRegistryEntry {
    Reserved {
        task_id: MeshTaskId,
        kind: AuxiliaryTaskKind,
        session_id: Option<String>,
        dedup_key: Option<String>,
    },
    Running(AuxiliaryTask),
}
```

If changing the registry type is too invasive, use a separate `HashSet<MeshTaskId>` or reservation map.

The ownership record must exist before the task future can publish completion.

## Phase 7 — Gate Task Start Until Registration Completes

Use a one-shot or watch gate:

```rust
let (start_tx, start_rx) = tokio::sync::oneshot::channel();
```

Spawn wrapper:

```rust
let handle = tokio::spawn(async move {
    if start_rx.await.is_err() {
        return cancelled_exit;
    }
    let reason = future.await;
    publish_auxiliary_exit(...);
    MeshTaskExit { ... }
});
```

Required sequence:

1. Acquire `auxiliary_submission_lock`.
2. Perform deduplication and capacity checks.
3. Remove stale entries.
4. Release registry lock.
5. Abort and await stale running tasks.
6. Insert reservation/`Running` entry with the new handle.
7. Signal `start_tx`.
8. Release submission lock.

Completion cannot race ahead of insertion because the future cannot start until the gate is opened.

## Phase 8 — Check Capacity Before Spawning Where Possible

The preferred sequence is to reserve capacity before creating the running future.

If task creation requires a `JoinHandle` for the registry:

- create a gated handle;
- insert it before opening the gate;
- if insertion fails, drop `start_tx`, abort and await the gated handle.

No user future should execute in a rejected branch.

## Phase 9 — Make Deduplication Atomic

Two concurrent submissions with the same dedup key must not both become active.

Under `auxiliary_submission_lock`:

- identify stale matching entries;
- remove them;
- reserve the replacement key;
- only then release the lock for stale-task abort/await if the reservation prevents another submitter from entering.

A simpler acceptable implementation is to hold the submission lock while aborting/awaiting stale tasks. Submission volume is low; avoid registry races over micro-optimizing lock duration.

## Phase 10 — Reaper Handling For Reservations

The reaper must tolerate:

- a completion event for a running entry;
- stale completion after dedup removal;
- shutdown while a reservation exists;
- cancelled gated task before start.

Unknown/stale task IDs should be logged at trace/debug, not treated as fatal.

## Phase 11 — Add Atomicity Tests

Required production-path tests:

### Immediate Completion

- submit an auxiliary future that returns immediately;
- assert registry entry exists before completion is processed;
- assert reaper removes and awaits it;
- registry returns to zero.

### Concurrent Duplicate Submissions

- launch two submissions concurrently with the same dedup key;
- assert at most one running entry remains;
- stale task, if created, is aborted and awaited;
- registry contains no duplicate key.

### Concurrent Capacity Boundary

- set capacity N;
- concurrently submit N+K distinct tasks;
- assert running/reserved entries never exceed N;
- rejected futures never execute;
- no orphan handles remain.

### Shutdown During Reservation

- block submission between reservation and start-gate release with a test hook;
- trigger shutdown;
- assert reservation and gated handle are finalized.

---

# Part C — Handle Informational Responses Correctly

## Phase 12 — Preserve HTTP Version In Response Head

Extend `FramedHttpResponseHead`:

```rust
http_version: HttpVersion,
```

Suggested enum:

```rust
enum HttpVersion {
    Http10,
    Http11,
}
```

Reject unsupported or malformed response versions.

Validate status codes are exactly three digits and in `100..=999`; preferably restrict to `100..=599` unless existing policy intentionally permits extension codes.

## Phase 13 — Add A Final-Response Reader

Extract:

```rust
async fn read_http_response_sequence<R: AsyncRead + Unpin>(
    reader: &mut R,
    request_method: &str,
    config: &ResponseFramingConfig,
) -> Result<FramedHttpResponse, HttpResponseFramingError>
```

Algorithm:

1. Read response head.
2. If status is `100..199`:
   - reject `101 Switching Protocols` because upgrades are unsupported;
   - consume its body according to no-body semantics;
   - optionally retain informational response bytes;
   - continue reading the next response head.
3. Stop at the first final status `>= 200`.
4. Frame the final response body normally.

## Phase 14 — Decide Informational Forwarding Policy

Choose one explicit behavior:

### Preferred Narrow Policy

Suppress informational responses and forward only the final response.

This is simplest for the one-request/one-response mesh contract.

### Alternative

Concatenate selected informational responses before the final response.

If this is chosen, ensure the client-side consumer supports multiple response heads.

Document the policy.

## Phase 15 — Add Informational Tests

Required cases:

- `100 Continue` followed by fixed-length 200;
- `103 Early Hints` followed by chunked 200;
- multiple informational responses before final;
- `101 Switching Protocols` rejected;
- backend closes after informational response without final response -> error;
- informational response coalesced with final response in one read.

---

# Part D — Make Response Transforms Framing-Safe

## Phase 16 — Skip Transforms For Raw Chunked Responses

For this narrow pass, do not pass raw chunked wire bodies through `apply_response_transforms()`.

Add explicit metadata to the framed response:

```rust
enum HttpResponseBodyEncoding {
    None,
    FixedLength,
    Chunked,
    CloseDelimited,
}
```

Before transforms:

```rust
if matches!(encoding, HttpResponseBodyEncoding::Chunked) {
    skip transforms;
}
```

Log at trace/debug if a transformable content type was skipped because the body is chunked.

## Phase 17 — Optionally Dechunk In A Future Pass

Document that transforming chunked responses requires:

- decoded entity bytes;
- transform;
- removal of `Transfer-Encoding`;
- updated `Content-Length`;
- trailer policy.

Do not partially implement this in Iteration 80.

## Phase 18 — Guard Fixed/Close-Delimited Transform Semantics

For fixed-length responses:

- transforms may rewrite `Content-Length`.

For close-delimited responses:

- after buffering and transforming, emit a `Content-Length` and remove/normalize `Connection` as needed before sending over QUIC.

Audit whether current transform code leaves contradictory framing headers.

## Phase 19 — Add Transform Tests

Required cases:

- transform-enabled chunked HTML is forwarded unmodified and still valid chunked wire format;
- transform-enabled fixed-length HTML updates `Content-Length` correctly;
- binary/non-UTF-8 body remains unmodified;
- close-delimited transformed response gets coherent framing.

---

# Part E — Restrict Close-Delimited Responses

## Phase 20 — Parse `Connection` Tokens Correctly

Replace exact-value comparison with case-insensitive comma-separated token parsing.

Helper:

```rust
fn header_contains_token(value: &str, token: &str) -> bool
```

Use for:

- `Connection: close`;
- request upgrade handling;
- future tokenized headers.

## Phase 21 — Apply Version-Aware Close-Delimited Policy

Allowed close-delimited cases:

- HTTP/1.0 response without `Content-Length` or chunked encoding;
- HTTP/1.1 response with explicit `Connection: close` and no other body framing.

Rejected case:

- HTTP/1.1 final response with no `Content-Length`, no chunked encoding, and no `Connection: close`.

Do not wait for idle timeout to discover ambiguous framing.

## Phase 22 — Correct Close-Delimited Limit Handling

If close-delimited body exceeds configured max:

- return an error;
- do not break and forward a truncated body.

Preserve idle and total body deadlines.

## Phase 23 — Add Close-Delimited Tests

Required cases:

- HTTP/1.0 close-delimited success;
- HTTP/1.1 `Connection: close` success;
- token list `Connection: keep-alive, close` success;
- HTTP/1.1 ambiguous no-length/no-close rejected immediately;
- close-delimited body limit exceeded -> error, no truncated forwarding;
- premature timeout -> error.

---

# Part F — Small Parser And Error Corrections

## Phase 24 — Correct Fixed-Length Extra-Prefix Error

When `body_prefix.len() > Content-Length`, return a fixed-length/trailing-bytes error, not `MalformedChunkedBody`.

Suggested variant:

```rust
ResponseBodyPrefixExceedsContentLength {
    prefix: usize,
    declared: usize,
}
```

## Phase 25 — Remove Obsolete Metadata Helpers

Remove unused:

- `extract_host_from_http()`;
- `extract_path_from_http()`;
- `extract_method_from_http()`.

All callers must use `ParsedHttpRequestMeta`.

Add a guardrail preventing reintroduction of whole-buffer metadata parsing.

## Phase 26 — Tighten Response Head Validation

Validate:

- exact `HTTP/1.0` or `HTTP/1.1` version;
- status token is exactly three ASCII digits;
- valid header line syntax;
- duplicate Host/request metadata remains handled by request parser;
- duplicate response `Content-Length` values are equal or rejected.

## Phase 27 — Remove Dead/Redundant Parser State

Audit response framing structs and helpers for unused fields and redundant parsing.

Keep one authoritative parser for:

- content length;
- transfer encoding;
- connection tokens;
- response version/status.

---

# Part G — File-Level Implementation Guide

## `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Implement:

- prefix-aware chunked parser;
- response sequence reader;
- informational response policy;
- response body encoding metadata;
- chunked transform bypass;
- version-aware close-delimited policy;
- tokenized `Connection` parsing;
- parser error corrections;
- obsolete helper removal.

## `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- `auxiliary_submission_lock`;
- gated auxiliary task start;
- reservation/atomic registration flow;
- race-safe dedup and capacity handling;
- shutdown cleanup of reservations/gated tasks;
- module-local concurrency tests.

## `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update if needed:

- auxiliary registry entry/reservation types;
- response body encoding or informational metadata types if shared;
- no new public API unless required outside the crate.

## Tests

Add or update:

- `tests/mesh_http_framing.rs` for prefix, informational, close-delimited, and transform cases;
- module-local auxiliary registration race tests;
- `tests/mesh_task_ownership_guard.rs` for atomic-registration and obsolete-helper guardrails.

---

# Part H — Behavioral Test Matrix

## Chunked Prefix Cases

Test all splits across:

- chunk-size line;
- extensions;
- payload;
- payload CRLF;
- zero chunk;
- trailers;
- final trailer terminator.

## Auxiliary Races

Use barriers to force:

- future completion before gate release;
- duplicate concurrent submission;
- capacity race;
- shutdown during reservation;
- stale completion after dedup replacement.

Assert registry size, handle destruction, exit publication, and no orphan tasks.

## Informational Responses

Use a local TCP backend that sends informational and final responses in:

- separate writes;
- one coalesced write;
- fragmented writes.

## Transform Safety

Enable minification configuration and prove raw chunked body remains unchanged.

## Close-Delimited Policy

Assert immediate rejection for ambiguous HTTP/1.1 framing rather than waiting for the idle timeout.

---

# Part I — Guardrails

Update `tests/mesh_task_ownership_guard.rs` to assert:

- auxiliary future cannot begin before registry insertion/start-gate release;
- auxiliary submissions use a serialization/reservation mechanism;
- capacity is enforced atomically;
- chunked parser consumes `body_prefix` as input;
- informational responses loop to a final response;
- chunked responses bypass transforms unless dechunked;
- HTTP/1.1 ambiguous close-delimited responses are rejected;
- obsolete request metadata extraction helpers are absent.

Behavioral tests remain authoritative.

---

# Ordered Handoff Sequence

A smaller model should implement in this order:

1. Build prefix-aware reader and fix chunked parser.
2. Add coalesced-prefix chunked tests.
3. Add response version/status validation.
4. Add informational response loop and tests.
5. Add response body encoding metadata.
6. Skip transforms for chunked responses and add tests.
7. Restrict close-delimited policy and fix limit errors.
8. Add auxiliary submission lock and gated start.
9. Add atomic reservation/dedup/capacity flow.
10. Add auxiliary race tests.
11. Remove obsolete metadata helpers.
12. Add guardrails and update docs.

Do not begin worker-level mesh supervision in this pass.

---

# Verification Commands

```bash
cargo test -p synvoid-mesh --features mesh http
cargo test -p synvoid-mesh --features mesh auxiliary
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test --test mesh_http_framing --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
```

If registry or parser types affect workspace callers:

```bash
cargo test --workspace --no-run
```

---

# Acceptance Criteria

This pass is complete when:

1. Chunked parsing consumes body-prefix bytes before socket reads.
2. Every prefix/socket split of chunk-size, payload, CRLF, zero chunk, and trailers is handled correctly.
3. Auxiliary completion cannot occur before ownership registration.
4. Concurrent dedup/capacity submissions cannot create duplicates or exceed capacity.
5. Rejected auxiliary futures never execute.
6. Informational responses are consumed until a final response is obtained.
7. `101 Switching Protocols` remains explicitly unsupported.
8. Raw chunked responses are not passed through entity-body transforms.
9. HTTP/1.1 close-delimited responses require explicit `Connection: close`.
10. Close-delimited limit overflow returns an error rather than truncated output.
11. Response version/status and connection-token parsing are strict and case-insensitive where required.
12. Obsolete whole-header metadata helpers are removed.
13. Real race and framing tests exercise production code.
14. No auxiliary task, reservation, stream handler, session, or response-framing operation survives successful shutdown or cleanup.
15. Worker-level mesh supervision remains documented as deferred.
16. Existing ownership, blocklist, threat-intel, provenance, mesh-ID, and composition guardrails remain green.

---

## Notes For The Implementer

This is the final narrow mesh transport correction.

Do not add broad abstractions. The two central fixes are straightforward:

> Parse already-read bytes before reading more.

> Register ownership before allowing a task to run or publish completion.
