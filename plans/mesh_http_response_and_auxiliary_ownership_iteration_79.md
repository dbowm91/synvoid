# Mesh HTTP Response Framing and Auxiliary Ownership Corrective Pass — Iteration 79

## Purpose

Iteration 78 corrected HTTP request framing and most remaining nested ownership issues. Fixed-length request bodies are preserved, header/body limits and framing deadlines exist, chunked requests and unsupported upgrade/tunnel semantics are rejected, edge-replica refresh work is registered as auxiliary work, and stream-handler drain diagnostics are propagated into peer-session and shutdown reports.

The review of `5791755dad242acb3c68b584a6e0b44362d215c4`, `38898416b9bf6cea1a770e249d6852b20243e315`, `e7597cc98d7193694b90bdeafbec000398e19a0e`, and `89686947452f73873f1cec03b7aa9bf1520c3418` found seven remaining correctness and ownership gaps:

1. Backend HTTP/1.1 responses are read until TCP EOF. A valid keep-alive response with `Content-Length` is therefore treated as incomplete and eventually fails on the backend idle timeout.
2. `extract_host_from_http()` and `extract_path_from_http()` decode the complete request buffer, including the body. Valid binary request bodies can cause metadata extraction to fail.
3. No-body requests with bytes already present after `\r\n\r\n` silently discard those bytes instead of rejecting ambiguous framing or pipelining.
4. Upgrade detection is substring-based rather than based on parsed header names and tokens.
5. Edge-replica refresh tasks return `MeshTaskExit` but do not publish `AuxiliaryTaskExit`, so normally completed refresh tasks can remain in `auxiliary_tasks` indefinitely.
6. Edge-refresh deduplication and capacity rejection abort handles without awaiting them, violating the abort-and-await ownership invariant.
7. `stop_peer_session_task_for_test()` is public in production only to support integration tests, unnecessarily expanding the crate API.

This pass should finish the HTTP-over-mesh proxy contract and make edge-replica refresh work conform fully to the existing auxiliary-task ownership model.

The primary invariant is:

> HTTP request and response boundaries must be determined from HTTP framing rather than connection closure or body decoding, and every auxiliary task must either complete through the auxiliary-exit/reaper path or be explicitly aborted and awaited before its registry entry is discarded.

---

## Current Known State

At `89686947452f73873f1cec03b7aa9bf1520c3418`:

- Request headers are read with idle and total deadlines.
- Fixed-length request bodies are preserved and forwarded.
- Header and body limits are enforced.
- Chunked request bodies are explicitly rejected.
- `CONNECT` and upgrade requests are rejected.
- Backend requests are buffered and written to a `TcpStream`.
- Backend responses are buffered by reading until EOF with an idle timeout.
- `handle_http_proxy_stream()` receives both `header_str` and complete request bytes.
- `extract_host_from_http()` and `extract_path_from_http()` still parse the complete byte buffer.
- `AuxiliaryTaskKind::EdgeReplicaRefresh` exists.
- Edge-refresh tasks are inserted into `auxiliary_tasks` with a deduplication key.
- The auxiliary reaper removes tasks only after an `AuxiliaryTaskExit` event or lag-triggered finished-handle scan.
- Duplicate edge-refresh tasks and over-capacity tasks are aborted but not awaited.
- `PeerSessionExit` contains `PeerStreamDrainReport`.
- Several real helper-level tests now exist, but persistent-backend and edge-refresh lifecycle tests remain missing.

---

## Non-Goals

Do not enable worker-level mesh supervision.

Do not redesign the HTTP proxy around full Hyper client/server integration unless the existing buffered implementation cannot be corrected safely.

Do not add HTTP/2 or HTTP/3 backend proxy support.

Do not implement request pipelining, `CONNECT`, WebSocket upgrade, or transparent bidirectional tunneling.

Do not broaden this pass into general edge-replica consistency redesign.

Do not expose new production APIs solely for integration testing.

---

# Part A — Define Backend HTTP Response Framing

## Phase 1 — Add A Parsed Response-Head Type

Add an internal type in `crates/synvoid-mesh/src/mesh/transport_peer.rs`:

```rust
struct FramedHttpResponseHead {
    header_bytes: Vec<u8>,
    body_prefix: Vec<u8>,
    status_code: u16,
    content_length: Option<usize>,
    chunked: bool,
    connection_close: bool,
}
```

The type must preserve bytes read after `\r\n\r\n` as `body_prefix`.

## Phase 2 — Add Response Framing Errors

Add typed errors or stable error messages for:

- malformed status line;
- invalid status code;
- response header too large;
- response header idle timeout;
- response header total timeout;
- invalid/conflicting `Content-Length`;
- ambiguous `Content-Length` plus chunked encoding;
- unsupported transfer coding;
- response body too large;
- premature EOF;
- malformed chunked body;
- backend closed before complete response.

Prefer a response-specific error enum if it keeps tests clear:

```rust
enum HttpResponseFramingError { ... }
```

## Phase 3 — Extract `read_http_response_head()`

Create a generic async helper for testability:

```rust
async fn read_http_response_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_header_bytes: usize,
) -> Result<FramedHttpResponseHead, HttpResponseFramingError>
```

Required behavior:

- read until `\r\n\r\n`;
- enforce remaining-capacity reads without overshoot;
- enforce both idle timeout and total deadline;
- parse the HTTP version and status code;
- parse `Content-Length` strictly;
- parse `Transfer-Encoding` tokens case-insensitively;
- parse `Connection` tokens case-insensitively;
- preserve coalesced body bytes.

## Phase 4 — Determine No-Body Responses

A response must be treated as bodyless when any of these applies:

- original request method was `HEAD`;
- status is 1xx;
- status is 204;
- status is 304.

Do not wait for `Content-Length` bytes in these cases, even if a malformed backend sends a misleading header.

Pass the original request method into backend response framing.

## Phase 5 — Support Fixed-Length Responses

Add:

```rust
async fn read_fixed_http_response_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Vec<u8>,
    content_length: usize,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpResponseFramingError>
```

Required behavior:

- preserve `body_prefix`;
- reject prefix larger than declared length;
- reject declared body over configured maximum before allocation;
- read exactly the missing bytes;
- return after declared body completion even if backend keeps TCP open;
- fail on premature EOF;
- enforce idle and total deadlines.

## Phase 6 — Support Chunked Backend Responses

Unlike request-side chunking, backend chunked responses are common and should be supported.

Implement a bounded raw chunked-body reader that preserves the original wire representation:

```rust
async fn read_chunked_http_response_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Vec<u8>,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_body_bytes: usize,
    max_trailer_bytes: usize,
) -> Result<Vec<u8>, HttpResponseFramingError>
```

Required semantics:

1. Parse hexadecimal chunk-size lines, ignoring permitted chunk extensions after `;`.
2. Preserve each original chunk-size line, chunk payload, and CRLF in the returned bytes.
3. Stop after a zero-size chunk and complete trailer block.
4. Bound total decoded or wire body bytes.
5. Bound trailer bytes.
6. Reject malformed sizes, missing CRLF, overflow, or premature EOF.
7. Enforce idle and total deadlines.

If this is too large for one pass, use Hyper’s HTTP/1 codec internally for response framing. Do not fall back to EOF-only framing for chunked responses.

## Phase 7 — Handle Close-Delimited Responses Explicitly

Close-delimited framing is acceptable only when no `Content-Length` or chunked encoding exists and the protocol semantics permit it.

Required behavior:

- for HTTP/1.0, close-delimited response may be accepted;
- for HTTP/1.1, accept close-delimited response only when `Connection: close` is present or policy explicitly allows it;
- enforce response body maximum;
- enforce idle and total response deadlines;
- EOF is the expected terminator only for this branch.

Do not use EOF as the general response boundary.

## Phase 8 — Reject Ambiguous Response Framing

Reject:

- conflicting duplicate `Content-Length` values;
- `Content-Length` plus chunked encoding;
- unsupported transfer codings;
- response bytes after a declared fixed-length body if pipelining is not supported and they were coalesced into the same read;
- malformed status/header syntax.

---

# Part B — Integrate Response Framing Into The Proxy Path

## Phase 9 — Add Response Configuration

Add or reuse authoritative limits:

```rust
pub max_peer_http_response_header_bytes: usize,
pub max_peer_http_response_body_bytes: usize,
pub peer_http_response_header_total_timeout_secs: u64,
pub peer_http_response_body_total_timeout_secs: u64,
pub max_peer_http_response_trailer_bytes: usize,
```

Continue using `peer_http_backend_idle_timeout_secs` as the per-read idle timeout.

Prefer reusing request limits only if the shared semantics are intentional and documented. Otherwise keep request/response limits separate.

## Phase 10 — Replace EOF Read Loop

Remove the unconditional backend loop that reads until `n == 0`.

New sequence:

1. Connect to backend.
2. Write complete request bytes.
3. Read/parse response head.
4. Determine body framing from request method, status, and headers.
5. Read exactly one framed response body.
6. Assemble `header_bytes + body_bytes`.
7. Apply response transforms.
8. Write response to QUIC stream.
9. Return without waiting for backend keep-alive closure.

## Phase 11 — Pass Parsed Request Metadata

Introduce a request metadata type:

```rust
struct ParsedHttpRequestMeta {
    method: String,
    target: String,
    version: String,
    host: String,
    upgrade_requested: bool,
    connection_upgrade: bool,
}
```

`handle_http_proxy_stream()` should receive this metadata plus complete request bytes.

Do not repeatedly parse metadata from the combined header+body buffer.

## Phase 12 — Preserve Response Transform Compatibility

`apply_response_transforms()` currently receives a complete buffered response.

Ensure the new response framer produces the same complete raw HTTP/1.x response representation:

```text
status line + headers + CRLFCRLF + body
```

For chunked responses, preserve chunked wire framing unless transforms require dechunking. If transforms operate on full wire bytes today, retain that contract.

Add tests proving transformed and untransformed response paths still receive complete bytes.

---

# Part C — Parse Request Metadata From Header Bytes Only

## Phase 13 — Add A Strict Request-Head Parser

Extend `FramedHttpRequestHead` or add:

```rust
struct ParsedHttpRequestHead {
    raw_header_bytes: Vec<u8>,
    method: String,
    target: String,
    version: String,
    host: String,
    content_length: Option<usize>,
    chunked: bool,
    upgrade_requested: bool,
    connection_upgrade: bool,
}
```

Required behavior:

- parse request line into exactly method, target, version;
- reject malformed or empty request line;
- parse exact header names case-insensitively;
- retain duplicate-header validation where required;
- parse `Host` from the header section only;
- never decode body bytes as UTF-8.

## Phase 14 — Remove Whole-Request UTF-8 Parsing

Replace usages of:

```rust
extract_host_from_http(&http_data)
extract_path_from_http(&http_data)
```

with parsed request metadata.

Delete or narrow those helpers so they accept header bytes or a header string only.

Binary body bytes must not influence:

- host selection;
- path extraction;
- method detection;
- ACME challenge detection;
- upgrade detection.

## Phase 15 — Parse `Host` Correctly

Required semantics:

- header name comparison case-insensitive;
- trim optional whitespace;
- preserve IPv6 bracket syntax;
- support host with optional port;
- reject missing host for HTTP/1.1;
- reject conflicting duplicate Host values;
- do not use naive `split(':').skip(1).collect()` because it breaks IPv6 literals.

Prefer a proper authority parser or conservative manual parsing.

## Phase 16 — Parse Upgrade Semantics By Header Tokens

Replace substring detection:

```rust
header_str.to_lowercase().contains("upgrade:")
```

with exact parsed semantics:

- `Upgrade` header present; or
- `Connection` header contains token `upgrade`.

Header token parsing must be comma-separated and case-insensitive.

Reject upgrade/tunnel requests with the existing explicit response.

## Phase 17 — Parse ACME Challenge Target From Request Line

Use parsed `target` rather than stripping a prefix from the complete header string.

Required behavior:

- only `GET` accepted;
- exact path prefix `/.well-known/acme-challenge/`;
- token stops at query delimiter if policy requires;
- reject CR/LF or invalid path characters.

---

# Part D — Reject Trailing Bytes And Pipelining

## Phase 18 — Reject Body Prefix For No-Body Framing

For `HttpBodyKind::None`:

```rust
if !head.body_prefix.is_empty() {
    return Err(HttpFramingError::AmbiguousTrailingBytes {
        count: head.body_prefix.len(),
    });
}
```

This prevents silently discarding:

- undeclared request bodies;
- pipelined requests;
- parser-smuggling payloads.

## Phase 19 — Reject Bytes Beyond Fixed `Content-Length`

`read_fixed_http_body()` already rejects a prefix larger than the declared length. Keep this behavior and add a specific error variant for pipelining/extra bytes if useful.

Do not forward or silently ignore extra bytes.

## Phase 20 — Make One-Request-Per-Stream Explicit

Document and enforce:

- one HTTP request per QUIC bidirectional stream;
- no pipelining;
- no subsequent request bytes after the framed body;
- stream closure/finish after one response.

Add guardrail and behavioral tests.

---

# Part E — Make Edge-Replica Refresh Fully Auxiliary-Owned

## Phase 21 — Add A Shared Auxiliary Spawn Helper

Extract the common auxiliary registration wrapper used by preflight and edge refresh:

```rust
async fn spawn_auxiliary_task<F>(
    &self,
    kind: AuxiliaryTaskKind,
    session_id: Option<String>,
    dedup_key: Option<String>,
    future: F,
) -> Result<MeshTaskId, AuxiliarySpawnError>
where
    F: Future<Output = MeshTaskExitReason> + Send + 'static;
```

Responsibilities:

1. Allocate task ID.
2. Enforce dedup/capacity before spawning where possible.
3. Spawn wrapper future.
4. Wrapper sends `AuxiliaryTaskExit` before returning.
5. Insert `AuxiliaryTask` in registry.
6. Ensure reaper can remove and await the handle.

Do not duplicate ad hoc registry logic in `RaftCommitNotification` handling.

## Phase 22 — Publish `AuxiliaryTaskExit`

The edge-refresh wrapper must send:

```rust
let _ = auxiliary_exit_tx.send(AuxiliaryTaskExit {
    task_id,
    reason,
});
```

before returning.

Use accurate reasons:

- `CleanCompletion` on successful query/update/delete;
- failure/error reason when leader query or replica update fails, if the auxiliary reason type supports it;
- cancellation remains represented by join cancellation when explicitly aborted.

## Phase 23 — Reap Normal Completion

Add a real test proving:

1. Edge-refresh task completes.
2. Completion event is sent.
3. Auxiliary reaper removes registry entry.
4. Reaper awaits the handle.
5. Registry returns to zero without shutdown or lag recovery.

This prevents the false capacity saturation defect.

## Phase 24 — Deduplicate Before Spawning

Reorder edge refresh submission:

1. Construct dedup key.
2. Lock registry.
3. Identify and remove stale matching task.
4. Count active edge-refresh tasks.
5. Decide whether replacement is allowed.
6. Unlock registry.
7. Abort and await removed stale task.
8. Spawn replacement only if accepted.
9. Re-lock and insert, or use a helper that handles race-safe insertion.

Do not spawn a task and then decide it should not exist.

## Phase 25 — Abort And Await Stale Deduplicated Tasks

When replacing a stale refresh:

```rust
old_task.handle.abort();
let _ = old_task.handle.await;
```

Await outside the registry lock.

Record cancellation in diagnostics if useful, but do not treat cache refresh cancellation as lifecycle failure.

## Phase 26 — Capacity Check Before Spawn

If active refreshes are at the cap:

- do not spawn a new task;
- increment a bounded metric/counter;
- emit rate-limited debug logging;
- return cleanly.

No handle should need aborting in the capacity-rejection branch.

## Phase 27 — Handle Registry Races

Because dedup and spawn occur across awaits, define race semantics explicitly.

Preferred options:

### Option A — Dedicated Queue Worker

Use one bounded worker with dedup/coalescing map. This avoids spawn/insert races entirely.

### Option B — Reservation Entry

Insert a lightweight reservation keyed by dedup key before spawning, then replace reservation with handle.

### Option C — Serialize Edge Refresh Submission

Use a dedicated mutex around dedup/capacity/spawn/insert.

For a smaller-model pass, Option C is acceptable if contention is negligible.

## Phase 28 — Ensure Shutdown And Recovery Finalize Refresh Work

Verify edge-refresh tasks are included in:

- normal auxiliary reaper cleanup;
- shutdown auxiliary drain;
- failed-state recovery auxiliary drain;
- rollback where relevant.

A completed task should normally self-reap before these paths.

---

# Part F — Improve Auxiliary Diagnostics

## Phase 29 — Distinguish Auxiliary Exit Reasons

If `AuxiliaryTaskExit` currently carries only broad task exit reasons, ensure edge-refresh errors are visible.

Suggested mapping:

```rust
MeshTaskExitReason::CleanCompletion
MeshTaskExitReason::Error(String)
MeshTaskExitReason::Cancelled
```

Do not return `CleanCompletion` after logging a failed leader query or replica update.

## Phase 30 — Add Low-Cardinality Metrics

Add counters without namespace/key labels:

- edge refresh submitted;
- edge refresh deduplicated;
- edge refresh dropped at capacity;
- edge refresh succeeded;
- edge refresh failed;
- edge refresh cancelled.

Metrics are optional if the repo’s metrics surface is not ready, but structured logs should distinguish these outcomes.

---

# Part G — Remove Production Test-Only API Surface

## Phase 31 — Move Session-Stop Tests Into The Defining Module

Remove public production exposure of:

```rust
pub async fn stop_peer_session_task_for_test(...)
```

Preferred implementation:

- add `#[cfg(test)] mod tests` inside `transport.rs`;
- call private `stop_peer_session_task()` directly;
- retain real JoinHandle tests there.

Alternative:

- create a `#[cfg(any(test, feature = "test-support"))]` test-support module;
- do not enable it in normal builds.

## Phase 32 — Remove Guardrails Requiring Public Test Adapter

Update guardrails so they verify behavior/tests exist without requiring production public visibility.

## Phase 33 — Preserve Existing Real Tests

Move or reproduce the three real cases:

- zero budget -> `ForcedParentAbort`;
- clean completion -> `Drained`;
- panic -> `Failed`.

Do not regress back to enum-construction tests.

---

# Part H — Behavioral Test Matrix

## Phase 34 — Binary Request Body Test

Use a request with:

- valid ASCII headers and `Host`;
- `Content-Length`;
- invalid UTF-8 body bytes.

Assert:

- host parsing succeeds;
- path parsing succeeds;
- exact binary body reaches the backend;
- no UTF-8 conversion is attempted on body bytes.

## Phase 35 — No-Body Trailing Bytes Test

Send:

```text
GET / HTTP/1.1\r\nHost: example.com\r\n\r\nEXTRA
```

Assert framing rejects ambiguous trailing bytes.

Add a pipelined second-request variant.

## Phase 36 — Exact Upgrade Parsing Tests

Cases:

- exact `Upgrade: websocket` -> rejected;
- `Connection: keep-alive, Upgrade` plus `Upgrade` -> rejected;
- unrelated header value containing text `upgrade:` -> not falsely rejected;
- header names with mixed case -> parsed correctly.

## Phase 37 — Persistent Backend Fixed-Length Response Test

Start a local TCP backend that:

1. accepts request;
2. writes a complete HTTP/1.1 response with `Content-Length`;
3. keeps the connection open longer than the old idle timeout.

Assert Synvoid:

- returns the complete response immediately after the declared body;
- does not wait for EOF;
- does not report a backend read timeout.

This is the most important regression test in the pass.

## Phase 38 — Chunked Backend Response Test

Backend sends a valid chunked response and keeps the socket open.

Assert:

- complete chunked response is forwarded;
- final zero chunk and trailers terminate framing;
- proxy returns without waiting for EOF.

Add malformed chunk-size and premature-EOF variants.

## Phase 39 — No-Body Backend Response Tests

Test:

- `HEAD` response;
- `204 No Content`;
- `304 Not Modified`;
- `1xx` handling according to chosen policy.

Assert no body wait occurs.

## Phase 40 — Close-Delimited Backend Test

Backend sends HTTP/1.0 or `Connection: close` response without length and then closes.

Assert close-delimited framing succeeds within limits.

## Phase 41 — Edge Refresh Normal Completion Test

Use a test future or mocked manager/client:

- submit one refresh;
- allow it to complete;
- assert `AuxiliaryTaskExit` is received;
- assert reaper removes and joins it;
- assert active refresh count returns to zero.

## Phase 42 — Edge Refresh Dedup Test

1. Start refresh A for `(namespace, key)` and block it.
2. Submit refresh B for the same key.
3. Assert A is removed, aborted, and awaited.
4. Assert only B remains.
5. Complete B and assert registry returns to zero.

Use a drop guard to prove A is destroyed before submission returns or before B is considered active.

## Phase 43 — Edge Refresh Capacity Test

1. Fill the configured refresh capacity with blocking tasks.
2. Submit one more distinct key.
3. Assert no new task is spawned.
4. Assert no orphan handle exists.
5. Assert capacity-drop diagnostic increments.

## Phase 44 — Auxiliary Failure Reason Test

Force leader query/update failure.

Assert completion event carries failure, not `CleanCompletion`.

---

# Part I — File-Level Implementation Guide

## Phase 45 — `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Implement:

- parsed request-head metadata;
- header-only Host/path/method/upgrade parsing;
- trailing-byte rejection;
- generic response-head reader;
- fixed-length response body reader;
- chunked response body reader;
- close-delimited response branch;
- response assembly and timeout enforcement;
- edge-refresh submission through shared auxiliary helper.

## Phase 46 — `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- shared auxiliary spawn/register wrapper;
- edge-refresh dedup/capacity serialization if placed here;
- correct completion event publication;
- abort-and-await stale auxiliary tasks;
- module-local tests for `stop_peer_session_task()`;
- removal of public test adapter.

## Phase 47 — `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update if needed:

- auxiliary exit reason diagnostics;
- reservation/submission types;
- no production test-only API types.

## Phase 48 — `crates/synvoid-mesh/src/mesh/config.rs`

Add/default/document response framing limits and deadlines.

Validate:

- header limits >= 4;
- body/trailer limits > 0;
- timeout values have explicit zero semantics;
- conversions are safe.

## Phase 49 — `crates/synvoid-config/src/mesh.rs`

Mirror all config additions and serde defaults.

## Phase 50 — Tests

Add or update:

- `tests/mesh_http_framing.rs` for generic request/response framing helpers;
- a local-backend integration test module for persistent and chunked responses;
- module-local transport tests for private session-stop logic;
- auxiliary ownership tests for completion, dedup, capacity, and failure reasons;
- ownership and framing guardrails.

---

# Part J — Guardrails

## Phase 51 — HTTP Response Framing Guardrails

Add source-level checks that:

- backend response is not unconditionally read until EOF;
- response `Content-Length` parsing exists;
- chunked response framing exists;
- no-body status/method handling exists;
- persistent connection test exists;
- response limits and deadlines exist.

Behavioral tests remain authoritative.

## Phase 52 — Header-Only Metadata Guardrails

Check that:

- Host/path parsing receives header metadata, not complete request bytes;
- whole-request `String::from_utf8(http_data.to_vec())` is removed;
- exact header-name parsing replaces substring-based upgrade detection;
- no-body body-prefix rejection exists.

## Phase 53 — Auxiliary Ownership Guardrails

Check that:

- edge refresh wrapper sends `AuxiliaryTaskExit`;
- stale dedup handles are awaited after abort;
- capacity is checked before spawning;
- normal completion can be reaped without lag recovery;
- edge refresh failures do not report `CleanCompletion`.

## Phase 54 — Public API Guard

Ensure `stop_peer_session_task_for_test` is absent from normal public builds.

---

# Part K — Documentation

## Phase 55 — Update HTTP-Over-Mesh Contract

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `skills/synvoid_mesh.md`;
- `AGENTS.md`;
- `crates/synvoid-mesh/AGENTS.override.md` if present.

Document:

- one request/response per QUIC stream;
- fixed/chunked/close-delimited backend response support;
- no-body response semantics;
- persistent backend connections no longer define response termination;
- binary request bodies are supported because metadata parsing is header-only;
- undeclared trailing bytes/pipelining are rejected;
- exact upgrade rejection semantics;
- edge-refresh completion/dedup/capacity ownership;
- worker-level mesh supervision remains deferred.

## Phase 56 — Remove Outdated Claims

Correct claims that:

- edge-refresh tasks fully self-reap before completion events exist;
- reading backend responses until EOF is a valid general HTTP/1.1 framing strategy;
- request metadata parsing is body-safe while whole-request UTF-8 decoding remains.

---

# Ordered Handoff Sequence

A smaller model should implement in this exact order:

1. Add parsed request metadata from header bytes only.
2. Reject no-body trailing bytes and replace substring-based upgrade checks.
3. Add generic backend response-head parser and tests.
4. Add fixed-length response-body framing.
5. Add no-body status/HEAD handling.
6. Add chunked backend response framing.
7. Add close-delimited fallback only for explicit cases.
8. Replace EOF-only backend response loop.
9. Add persistent-backend and chunked-response integration tests.
10. Extract shared auxiliary spawn wrapper.
11. Make edge refresh publish `AuxiliaryTaskExit`.
12. Move dedup/capacity checks before spawn.
13. Abort and await stale refresh tasks.
14. Add edge-refresh completion/dedup/capacity/failure tests.
15. Move session-stop tests into module-local tests and remove public adapter.
16. Add guardrails.
17. Update documentation.

Do not begin worker-level mesh supervision during this pass.

---

# Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-mesh --features mesh http
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test -p synvoid-mesh --features mesh auxiliary
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test --test mesh_http_framing --features mesh,dns
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

Run lifecycle and regression checks:

```bash
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test background_task_ownership_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --lib --no-run
cargo fmt --check
cargo clippy -p synvoid-mesh --features mesh,dns -- -D warnings
```

If config or lifecycle types affect workspace callers:

```bash
cargo test --workspace --no-run
```

Record known certificate-test failures separately and confirm they reproduce on the base commit before classifying them as pre-existing.

---

# Acceptance Criteria

This pass is complete only when all of the following are true:

1. A backend HTTP/1.1 response with `Content-Length` completes without waiting for TCP EOF.
2. Chunked backend responses are framed to the zero chunk and trailers without waiting for EOF.
3. HEAD, 1xx, 204, and 304 responses do not wait for a body.
4. Close-delimited response framing is used only for explicit compatible cases.
5. Backend response header/body/trailer limits and idle/total deadlines are enforced.
6. Host, path, method, and upgrade metadata are parsed from header bytes only.
7. Binary request bodies do not break Host/path extraction.
8. No-body requests with trailing bytes or pipelined data are rejected.
9. Upgrade detection uses exact parsed header names/tokens rather than substring matching.
10. Edge-replica refresh tasks publish `AuxiliaryTaskExit` on normal completion.
11. Normally completed edge-refresh tasks are reaped without shutdown or lag recovery.
12. Deduplicated stale refresh tasks are aborted and awaited.
13. Capacity rejection occurs before spawning and creates no orphan handle.
14. Edge-refresh failures are reported as failures rather than clean completion.
15. `stop_peer_session_task_for_test` is absent from the normal production public API.
16. Real tests cover binary bodies, trailing-byte rejection, persistent backend responses, chunked responses, edge-refresh completion, dedup, capacity, and failure.
17. No lifecycle-owned stream handler, datagram child, auxiliary refresh task, session, connection, or runtime resource survives successful shutdown, rollback, or recovery.
18. Worker-level mesh supervision remains accurately documented as deferred.
19. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker-lifecycle, and mesh-ownership guardrails remain green.

---

## Notes For The Implementer

This is a narrow final proxy and auxiliary-ownership pass.

Three rules govern the implementation:

> HTTP/1.1 message completion is determined by framing, not by whether the TCP peer closes the connection.

> Request metadata comes from the header section; the body may be arbitrary bytes.

> Aborting an auxiliary task is not cleanup until its handle has been awaited.
