# Mesh Transport HTTP Framing and Nested Ownership Corrective Pass — Iteration 78

## Purpose

Iteration 77 corrected the remaining lifecycle-level nested cleanup defects: stream-handler draining is deadline-aware, read timeouts are placed on actual reads, forced parent-session aborts are classified fail-closed, recovery aggregates session cleanup errors, and incoming datagram handlers are owned by a bounded `JoinSet`.

The review of `d64bc9372a449a47799b3c70b7e688d0c093b422`, `f690be7847ac2933bf58a8eb92fc99854878ef8b`, and `b26ce9d49a8ec1c6aa9827eb53dcd0ab8134bf06` found six remaining transport correctness and observability issues:

1. HTTP-over-mesh framing stops after `\r\n\r\n` and forwards only the bytes already read, so `POST`/`PUT`/`PATCH` bodies can be truncated or omitted.
2. The HTTP header-cap calculation can overshoot the configured maximum because each read uses the full buffer size rather than the remaining capacity.
3. Each header read receives a fresh idle timeout, so a slow peer can hold a handler for an excessive total framing duration while staying just under the idle threshold.
4. `RaftCommitNotification` handling still launches an unowned edge-replica refresh with bare `tokio::spawn()`.
5. Per-stream handler failures and panics are counted in `PeerStreamDrainReport` but discarded when constructing `PeerSessionExit`.
6. Several Iteration 77 tests simulate expected behavior instead of invoking the actual private helpers or transport paths.

This pass should correct HTTP request framing, close the remaining nested datagram ownership exception, preserve nested failure diagnostics, and replace simulated tests with implementation-level tests.

The primary invariant is:

> Mesh HTTP framing must preserve the complete request bytes it claims to proxy, every nested asynchronous operation must remain under bounded transport ownership, and tests must execute the production cleanup/framing helpers rather than merely reproducing their intended logic.

---

## Current Known State

At `b26ce9d49a8ec1c6aa9827eb53dcd0ab8134bf06`:

- `peer_message_loop()` owns per-stream handlers in a bounded `JoinSet`.
- `drain_peer_stream_handlers()` uses a deadline-aware timeout and abort-and-await fallback.
- `peer_message_timeout_secs` applies to actual QUIC read operations.
- `peer_stream_total_timeout_secs` optionally bounds the full handler lifetime.
- HTTP framing:
  - reads until `\r\n\r\n`;
  - caps headers with `max_peer_http_header_bytes`;
  - passes the collected buffer directly to `handle_http_proxy_stream()`.
- `handle_http_proxy_stream()` writes that buffer to the backend as the complete request.
- datagram handler tasks are owned by a bounded local `JoinSet`.
- `RaftCommitNotification` still creates an unowned edge-replica refresh task.
- `PeerStreamDrainReport` records drained/aborted/failed child handlers.
- `PeerSessionExit` carries only session identity, node identity, generation, and a broad exit reason.
- several tests in `tests/mesh_forced_cleanup.rs` still construct reports/enums or independent toy `JoinSet`s rather than calling actual implementation helpers.

---

## Non-Goals

Do not enable worker-level mesh supervision.

Do not redesign HTTP proxy policy, WAF behavior, routing policy, or backend selection.

Do not implement full HTTP/2 or HTTP/3 proxy semantics in this pass.

Do not redesign the mesh protocol beyond adding internal framing helpers or metadata types.

Do not convert the entire mesh HTTP proxy to Hyper unless required to fix correctness cleanly.

Do not broaden this pass into unrelated edge-replica consistency changes.

---

# Part A — Define The Supported HTTP-Over-Mesh Framing Contract

## Phase 1 — Document The Current Protocol Boundary

Before changing code, document what the mesh stream carries.

Choose one explicit contract:

### Preferred Contract

A single QUIC bidirectional stream carries exactly one HTTP/1.x request and one HTTP/1.x response.

Supported request framing:

- request line and headers terminated by `\r\n\r\n`;
- no body;
- fixed body with valid `Content-Length`;
- chunked request body if implemented in this pass;
- connection closes or stream finishes after one request.

Unsupported or rejected explicitly:

- multiple pipelined requests on one QUIC stream;
- ambiguous `Content-Length` plus `Transfer-Encoding` combinations;
- invalid duplicate `Content-Length` values;
- unsupported transfer codings;
- request bodies over configured limits.

Do not silently accept partially supported framing.

## Phase 2 — Introduce A Parsed Framing Result

Add an internal type in `transport_peer.rs` or `lifecycle.rs`:

```rust
struct FramedHttpRequest {
    header_bytes: Vec<u8>,
    body_prefix: Vec<u8>,
    body_kind: HttpBodyKind,
}

enum HttpBodyKind {
    None,
    ContentLength(usize),
    Chunked,
}
```

Alternative:

```rust
struct FramedHttpRequest {
    bytes: Vec<u8>,
    header_end: usize,
    content_length: Option<usize>,
    chunked: bool,
}
```

The type must preserve body bytes already coalesced into the same QUIC read that completed the headers.

## Phase 3 — Add Explicit Framing Errors

Add typed or clearly distinguishable errors for:

- header too large;
- header framing timeout;
- total framing timeout;
- invalid HTTP header syntax;
- conflicting `Content-Length` values;
- `Content-Length` plus unsupported `Transfer-Encoding`;
- unsupported transfer coding;
- body too large;
- premature EOF;
- malformed chunked framing.

If adding new `MeshTransportError` variants is too broad, use `ReceiveFailed` with stable prefixes and tests.

---

# Part B — Fix Header Framing And Capacity Enforcement

## Phase 4 — Extract `read_http_request_head()`

Add a dedicated helper:

```rust
async fn read_http_request_head(
    recv: &mut RecvStream,
    first_byte: u8,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_header_bytes: usize,
) -> Result<FramedHttpRequestHead, MeshTransportError>
```

Suggested result:

```rust
struct FramedHttpRequestHead {
    header_bytes: Vec<u8>,
    body_prefix: Vec<u8>,
    content_length: Option<usize>,
    transfer_encoding: Option<String>,
}
```

## Phase 5 — Enforce The Header Cap Without Overshoot

Before every read:

```rust
let remaining_capacity = max_header_bytes
    .checked_sub(buffer.len())
    .ok_or_else(header_too_large)?;

if remaining_capacity == 0 {
    return Err(header_too_large());
}

let read_size = remaining_capacity.min(temp.len());
```

After appending:

```rust
if buffer.len() > max_header_bytes {
    return Err(header_too_large());
}
```

Do not use `header_cap.min(temp.len())` independently of current buffer length.

Remove the unused `accumulated` variable.

## Phase 6 — Split Header Bytes From Body Prefix

When `\r\n\r\n` is found, calculate:

```rust
let header_end = marker_index + 4;
let header_bytes = buffer[..header_end].to_vec();
let body_prefix = buffer[header_end..].to_vec();
```

Do not discard or misclassify bytes that arrived after the terminator in the same read.

## Phase 7 — Add A Total Header-Framing Deadline

Add config:

```rust
pub peer_http_header_total_timeout_secs: u64
```

Recommended default: 30 seconds or another policy-appropriate bound.

Use both:

- `peer_message_timeout_secs` as the idle timeout for each read;
- `peer_http_header_total_timeout_secs` as one total deadline for the complete header block.

Pattern:

```rust
let deadline = Instant::now() + total_timeout;
let read_budget = idle_timeout.min(deadline.saturating_duration_since(Instant::now()));
```

If the total deadline expires, fail even if each individual read arrived before the idle timeout.

## Phase 8 — Reject Zero Or Invalid Header Limits Safely

Configuration validation should ensure:

- `max_peer_http_header_bytes >= 4`;
- header timeout values are nonzero or have explicitly documented disabled semantics;
- integer conversions are safe.

Add serde/default validation tests.

---

# Part C — Parse Body Framing Safely

## Phase 9 — Parse `Content-Length` Strictly

Parse headers case-insensitively.

Required behavior:

- no `Content-Length` -> no fixed-length body unless chunked;
- one valid value -> fixed body length;
- duplicate equal values -> choose whether to accept; preferred: accept only if all normalized values are equal;
- conflicting duplicates -> reject;
- negative, non-numeric, overflow -> reject;
- value above configured maximum -> reject.

Add config:

```rust
pub max_peer_http_body_bytes: usize
```

Choose a default aligned with existing proxy/request body limits.

Do not create a separate inconsistent body limit if an existing authoritative limit already exists; reuse it.

## Phase 10 — Parse `Transfer-Encoding`

At minimum:

- detect `chunked` case-insensitively;
- reject unsupported codings;
- reject ambiguous `Content-Length` plus chunked combinations;
- do not forward malformed framing to the backend.

Choose one implementation outcome.

### Outcome A — Implement Chunked Body Collection

Read and preserve chunk-size lines, chunk payloads, delimiters, final zero chunk, and trailers up to configured bounds.

Forward the original chunked wire representation if the backend connection receives raw HTTP/1.x bytes.

### Outcome B — Reject Chunked Requests Explicitly

Return a clear transport/proxy error or HTTP response until chunked support is implemented.

Do not silently treat a chunked request as header-only.

Preferred: Outcome A if implementation scope remains contained; otherwise explicit rejection is acceptable for this corrective pass.

## Phase 11 — Add A Request-Body Framing Helper

For fixed bodies:

```rust
async fn read_fixed_http_body(
    recv: &mut RecvStream,
    prefix: Vec<u8>,
    content_length: usize,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> Result<Vec<u8>, MeshTransportError>
```

Required behavior:

- reject `prefix.len() > content_length` unless pipelining semantics are explicitly supported;
- allocate only after body-size validation;
- preserve prefix bytes;
- read exactly the remaining bytes;
- fail on premature EOF;
- enforce idle and total body-framing deadlines.

## Phase 12 — Add A Total Body-Framing Deadline

Add config if needed:

```rust
pub peer_http_body_total_timeout_secs: u64
```

Alternatively reuse `peer_stream_total_timeout_secs` only if its semantics are appropriate and enabled by default for HTTP body framing.

Preferred separation:

- per-read idle timeout;
- total header framing timeout;
- total body framing timeout;
- optional total handler lifetime timeout.

Document each clearly.

## Phase 13 — Construct The Complete Forwarded Request

After framing:

```rust
let mut request = header_bytes;
request.extend_from_slice(&body_bytes);
```

Pass the complete request to `handle_http_proxy_stream()`.

For chunked Outcome A, include the exact chunked body bytes.

For no-body requests, forward only the headers.

---

# Part D — Avoid Buffering Regressions Where Streaming Is Required

## Phase 14 — Decide Buffered Versus Streaming Proxy Semantics

The existing implementation buffers the full backend response, so fully buffered request bodies are consistent with current architecture for bounded requests.

However, review whether these cases require streaming:

- large uploads;
- chunked requests;
- server-sent events;
- long-lived request bodies;
- upgrade/CONNECT traffic.

For this iteration, choose one explicit scope:

### Preferred Narrow Scope

- support bounded fixed-length request bodies;
- explicitly reject chunked bodies and protocol upgrades if not already supported;
- retain buffered backend response behavior;
- document that streaming proxy semantics are deferred.

This is safer than partially implementing transparent streaming.

## Phase 15 — Handle `CONNECT` And Upgrade Requests Explicitly

The first-byte classifier includes `CONNECT`, but the backend path is not a tunnel implementation.

Audit:

- `CONNECT`;
- `Connection: upgrade`;
- `Upgrade: websocket`;
- HTTP/1.1 pipelining.

Reject unsupported upgrade/tunnel semantics explicitly rather than forwarding a request into a backend path that buffers until EOF.

## Phase 16 — Prevent Backend Response Reads From Hanging Indefinitely

Although not the primary regression, `handle_http_proxy_stream()` currently reads backend response bytes until EOF with no idle or total timeout.

Add or reuse backend response timeout policy:

```rust
pub peer_http_backend_read_idle_timeout_secs: u64
pub peer_http_backend_total_timeout_secs: Option<u64>
```

At minimum, add an idle read timeout so a backend that never closes cannot pin a stream forever when total stream timeout is disabled.

Keep this narrowly scoped and aligned with existing proxy timeout configuration if available.

---

# Part E — Own Edge-Replica Notification Work

## Phase 17 — Remove Bare Spawn From `RaftCommitNotification`

Replace the bare `tokio::spawn()` with transport-owned bounded work.

Choose one architecture.

### Preferred — Auxiliary Task Registry

Register the edge-replica refresh through the existing auxiliary task registry.

Suggested task kind:

```rust
AuxiliaryTaskKind::EdgeReplicaRefresh
```

Metadata:

- namespace;
- key ID hash or bounded diagnostic identifier;
- no high-cardinality metrics labels;
- no peer-session association required unless useful.

The auxiliary reaper should remove and await completion as it does for preflight tasks.

### Alternative — Dedicated Bounded Worker

Create a bounded `mpsc` queue and one transport-owned worker task.

Benefits:

- naturally bounds commit-notification bursts;
- can coalesce duplicate `(namespace, key)` updates;
- avoids one task per notification.

Preferred if notification frequency can be high.

## Phase 18 — Define Backpressure And Coalescing

For a queue-based worker:

- fixed queue capacity;
- `try_send()` from datagram handling;
- on full queue, coalesce or drop duplicate cache refreshes;
- log/metric drops at low cardinality;
- stale cache remains acceptable but behavior is observable.

For auxiliary-task registry:

- enforce a maximum concurrent edge-replica refresh count;
- deduplicate by `(namespace, key)` where practical;
- do not permit unbounded task accumulation.

## Phase 19 — Ensure Shutdown/Recovery Owns Refresh Work

Owned edge-replica refresh tasks must:

- stop accepting new work when mesh shutdown begins;
- drain to a bounded deadline;
- abort and await remaining work;
- not mutate the edge replica after transport shutdown returns.

If using the existing auxiliary registry, verify normal shutdown and recovery already cover this task kind.

## Phase 20 — Reassess Other Documented Spawn Exceptions

Audit:

- one-shot edge-replica manager initialization;
- DHT `send_find_node`;
- DHT `send_ping`.

For each, classify as:

- truly synchronous enough to await inline;
- transport-owned auxiliary work;
- protocol transport callback where fire-and-forget is required by trait shape.

Do not automatically change all three in this pass, but document why each remaining exception cannot mutate state after shutdown or how failure is bounded.

---

# Part F — Preserve Nested Stream Failure Diagnostics

## Phase 21 — Extend `PeerSessionExit`

Add child-drain diagnostics:

```rust
pub struct PeerSessionExit {
    pub session_id: String,
    pub node_id: String,
    pub reason: PeerSessionExitReason,
    pub generation: u64,
    pub stream_drain: PeerStreamDrainReport,
}
```

Alternative: add only when nonzero, but a concrete report is simpler.

Update all constructors and consumers.

## Phase 22 — Define Session Failure Semantics

Decide how child failures affect the broad session reason.

Recommended:

- malformed message/ordinary handler error: keep connection/session reason but preserve `failed > 0` in report;
- child panic: promote session reason to `Failed` or add `PeerSessionExitReason::ChildTaskFailed`;
- forced child abort during normal cancellation: keep `Cancelled`, with `aborted > 0` in report;
- forced child abort on connection close: keep `ConnectionClosed`, with report.

Do not hide panics behind `ConnectionClosed` without any durable diagnostic.

## Phase 23 — Propagate To Shutdown And Metrics

Extend `MeshShutdownReport` or internal metrics to count:

- stream handlers drained;
- stream handlers aborted;
- stream handlers failed/panicked.

Avoid peer/session IDs in metric labels.

At minimum, log one structured summary per session exit.

## Phase 24 — Preserve Reaper Information

The session exit reaper should retain or publish the `PeerStreamDrainReport` before removing the task entry.

If there is a session-exit broadcast channel, include the report in the event.

---

# Part G — Replace Simulated Tests With Real Implementation Tests

## Phase 25 — Test `drain_peer_stream_handlers()` Directly

The code already exposes a `#[cfg(test)]` adapter.

Add a unit test in the defining crate/module rather than an external integration test that cannot see `cfg(test)` exports.

Test:

1. Spawn one never-ending handler with a drop guard.
2. Call the real drain helper with a short timeout.
3. Assert elapsed time is bounded.
4. Assert `aborted == 1`.
5. Assert drop guard fired before return.
6. Assert `JoinSet` is empty.

Add mixed outcome case:

- one clean;
- one returns `Err`;
- one panics;
- one hangs.

Assert exact counts.

## Phase 26 — Test `stop_peer_session_task()` Directly

Add an internal unit test adapter under `#[cfg(test)]` if necessary.

Cases:

- zero budget + pending parent -> `ForcedParentAbort`;
- positive budget + clean parent -> `Drained`;
- positive budget + parent panic -> `Failed`;
- timeout + pending parent -> `ForcedParentAbort`;
- drop guard fires before return.

Do not only instantiate enum variants.

## Phase 27 — Test Recovery Session Error Aggregation Through The Real Path

Prefer a transport fixture or focused internal helper test that invokes actual recovery issue aggregation.

At minimum extract:

```rust
fn assemble_recovery_issues(
    session_errors: Vec<String>,
    remaining_errors: Vec<String>,
    ...
) -> Vec<String>
```

and test the real helper.

Preferred: construct a `Failed` transport with a session requiring forced parent abort and call `recover_failed_state(Duration::ZERO)`.

## Phase 28 — Test `drain_datagram_handlers()` Directly

Add a test adapter under `#[cfg(test)]`.

Cases:

- clean completion;
- hung task aborted and awaited;
- panic observed;
- zero timeout;
- `JoinSet` empty before return.

The existing independent toy `JoinSet` test is insufficient.

## Phase 29 — Add HTTP Framing Unit Tests

Use a testable read abstraction if creating real `quinn::RecvStream` fixtures is impractical.

Preferred extraction:

```rust
async fn read_http_request_from<R: AsyncRead + Unpin>(...)
```

Production can wrap `RecvStream`; tests can use `tokio::io::duplex()`.

Required cases:

### Header-Only GET

- fragmented across multiple writes;
- terminator detected;
- exact bytes preserved.

### Fixed-Length POST

- headers and body split across writes;
- complete body forwarded.

### Coalesced Header And Body Prefix

- final header bytes and part/all body arrive in one read;
- prefix preserved exactly;
- remaining bytes read correctly.

### Premature EOF

- declared body longer than received;
- error returned.

### Oversized Header

- cap exceeded by one byte;
- error returned;
- no overshoot accepted.

### Conflicting Content Length

- reject.

### Chunked Request

- either parse correctly or reject explicitly, matching chosen outcome.

### Slow Header Total Deadline

- individual reads stay below idle timeout;
- total framing deadline expires.

### Body Limit

- exact limit accepted;
- limit + 1 rejected before large allocation.

## Phase 30 — Add End-To-End Proxy Body Test

Where practical, use:

- local TCP backend listener;
- test QUIC/stream abstraction or extracted framing helper;
- fixed-length POST request.

Assert backend receives the exact full request bytes, including body.

## Phase 31 — Add Edge-Replica Ownership Test

For auxiliary registry or worker design:

1. enqueue/start a refresh task that blocks;
2. trigger shutdown/recovery;
3. assert task is aborted/awaited or worker drains;
4. assert no edge-replica mutation occurs after cleanup returns;
5. assert queue/concurrency limit is enforced.

---

# Part H — File-Level Implementation Guide

## Phase 32 — `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Implement:

- HTTP head framing helper;
- strict remaining-capacity calculation;
- idle + total header deadlines;
- `Content-Length` parsing;
- fixed body read helper;
- explicit chunked support or rejection;
- complete request construction;
- backend idle timeout if included;
- edge-replica notification ownership handoff;
- `PeerSessionExit.stream_drain` population.

## Phase 33 — `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update:

- `PeerSessionExit` with `PeerStreamDrainReport`;
- optional new child-failure reason;
- optional HTTP framing diagnostic types if shared.

## Phase 34 — `crates/synvoid-mesh/src/mesh/config.rs`

Add/default/document:

- `peer_http_header_total_timeout_secs`;
- `max_peer_http_body_bytes` or reuse existing authoritative limit;
- `peer_http_body_total_timeout_secs`;
- optional backend response idle timeout;
- edge-replica refresh concurrency/queue limit if needed.

## Phase 35 — `crates/synvoid-config/src/mesh.rs`

Mirror config fields and serde defaults exactly.

## Phase 36 — `crates/synvoid-mesh/src/mesh/transport.rs`

If using the auxiliary registry:

- add edge-replica refresh task kind and spawn helper;
- ensure shutdown/recovery drains it;
- propagate session stream-drain reports into aggregate shutdown reporting.

## Phase 37 — Tests

Add or update:

- module-local tests for private helpers;
- `tests/mesh_forced_cleanup.rs` only for public/integration behavior;
- new `tests/mesh_http_framing.rs` if extracted helpers are public enough;
- guardrail tests for body framing and owned edge-replica work.

---

# Part I — Guardrails

## Phase 38 — Update `tests/mesh_task_ownership_guard.rs`

Add checks that:

- `RaftCommitNotification` no longer contains bare `tokio::spawn()`;
- edge-replica refresh uses auxiliary ownership or a bounded worker;
- `PeerSessionExit` carries stream-drain diagnostics;
- child stream panic/failure is not silently discarded.

## Phase 39 — Add HTTP Framing Guardrails

Add source-level checks that:

- header read size uses remaining capacity;
- body framing exists after `\r\n\r\n`;
- `Content-Length` is parsed or chunked requests are explicitly rejected;
- the complete request, not headers only, is forwarded;
- total header-framing deadline exists;
- unused `accumulated` bookkeeping is absent.

Behavioral tests remain authoritative.

## Phase 40 — Reject Placeholder Behavioral Tests

Add a review/guardrail convention:

- tests named `behavioral` must invoke production code or a direct test adapter;
- no test should satisfy a behavior by manually assigning `report.aborted = 1` or constructing the expected enum variant;
- documentary tests should be named accordingly.

This may be enforced by code review rather than brittle source tests.

---

# Part J — Documentation

## Phase 41 — Update Mesh Lifecycle And Protocol Docs

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `skills/synvoid_mesh.md`;
- `AGENTS.md`;
- `crates/synvoid-mesh/AGENTS.override.md` if present.

Document:

- one-request-per-stream HTTP contract;
- supported request body framing;
- body/header limits;
- idle versus total framing deadlines;
- unsupported chunked/upgrade semantics if deferred;
- owned edge-replica refresh work;
- child stream-drain diagnostics in session exits;
- worker-level mesh supervision remains deferred.

## Phase 42 — Correct Existing Claims

Remove or revise claims that:

- HTTP header framing alone is sufficient request framing;
- all datagram-path work is owned while the edge-replica spawn remains detached;
- Iteration 77 behavioral tests exercise actual helpers when they only simulate behavior.

---

# Ordered Handoff Sequence

A smaller model should implement in this exact order:

1. Extract a testable HTTP head-framing helper.
2. Fix remaining-capacity calculation and add total header deadline.
3. Preserve body-prefix bytes after the header terminator.
4. Parse and validate `Content-Length` and transfer encoding.
5. Add bounded fixed-length body reading.
6. Choose and implement chunked support or explicit rejection.
7. Forward the complete request bytes.
8. Add direct framing tests with `tokio::io::duplex()` or equivalent.
9. Move edge-replica refresh under auxiliary-task or worker ownership.
10. Extend `PeerSessionExit` with stream-drain diagnostics.
11. Add direct tests for stream drain, session stop, datagram drain, and recovery aggregation.
12. Add guardrails.
13. Update documentation.

Do not begin worker-level mesh supervision during this pass.

---

# Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test -p synvoid-mesh --features mesh http
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_http_framing --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
```

Run regressions:

```bash
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
```

If config or lifecycle event types affect workspace callers:

```bash
cargo test --workspace --no-run
```

Record known certificate-test failures separately and confirm they reproduce at the base commit before classifying them as pre-existing.

---

# Acceptance Criteria

This corrective pass is complete only when all of the following are true:

1. HTTP header framing cannot exceed `max_peer_http_header_bytes`, even by one read-buffer chunk.
2. A total header-framing deadline bounds slow-fragment attacks independently of per-read idle timeout.
3. Body bytes coalesced with the final header read are preserved.
4. Fixed-length request bodies are read completely or rejected on premature EOF.
5. Request bodies over the configured limit are rejected before excessive allocation.
6. Conflicting or malformed body framing is rejected.
7. Chunked requests are either implemented correctly or rejected explicitly.
8. The backend receives the exact complete request bytes for supported request types.
9. Unsupported `CONNECT`/upgrade/pipelining semantics are rejected explicitly.
10. Edge-replica refresh work is transport-owned, concurrency-bounded, and finalized on shutdown/recovery.
11. `PeerSessionExit` preserves child stream drain/abort/failure diagnostics.
12. Child stream panics remain observable in session/shutdown diagnostics.
13. Real tests invoke production HTTP framing, stream-drain, session-stop, datagram-drain, and recovery aggregation helpers.
14. No test labeled behavioral merely constructs the expected enum/report without invoking implementation code.
15. No lifecycle-owned stream handler, datagram child, edge-replica refresh task, session, auxiliary task, connection, or runtime resource survives successful shutdown, rollback, or recovery.
16. Worker-level mesh supervision remains accurately documented as deferred.
17. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker-lifecycle, and mesh-ownership guardrails remain green.

---

## Notes For The Implementer

This pass is primarily a transport correctness correction, not another lifecycle redesign.

Two rules govern the work:

> Finding `\r\n\r\n` completes the HTTP header, not necessarily the HTTP request.

> A documented fire-and-forget task is still unowned unless a lifecycle component can bound and finalize it.
