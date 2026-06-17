# Mesh Transport Subsystem Closure — Iteration 81

## Purpose

Iteration 80 implemented the planned final transport corrections: prefix-aware chunked response parsing, gated auxiliary-task start, serialized auxiliary deduplication/capacity checks, informational-response handling, chunked transform bypass, strict HTTP/1.1 close-delimited policy, response parser cleanup, and substantial framing/race tests.

The current head at `1a747f8c0bbc53e4dd083d99c57624d4f5f709c4` is architecturally sound, but six concrete closure issues remain:

1. `read_http_response_sequence()` preserves a complete coalesced final response head, but loses a *partial* final head left over after an informational response.
2. Close-delimited response reads enforce only a per-read idle timeout, not the configured total body deadline.
3. Chunked trailer bytes are not independently capped by `max_peer_http_response_trailer_bytes` after the zero-size chunk.
4. Response status/version parsing is duplicated and less strict than documented.
5. Auxiliary submission is serialized against other submissions, but not against shutdown/recovery draining, so new auxiliary work can be inserted after cleanup has begun.
6. The newest race tests validate the pattern using hand-built maps/gates rather than invoking the production `spawn_auxiliary_task()` path on a real transport fixture.

This plan is intentionally narrow. Completing it should allow the mesh transport/lifecycle subsystem to be formally closed and the next architectural target to move to worker-level mesh supervision.

The core invariants are:

> Bytes already consumed from the backend remain part of the framing state until parsed or rejected.

> Every response body mode is bounded by both idle and total deadlines.

> Shutdown and recovery exclude new auxiliary submissions before draining ownership registries.

> Closure tests must execute the production path, not merely reconstruct its intended algorithm.

---

## Current Known State

At `1a747f8c0bbc53e4dd083d99c57624d4f5f709c4`:

- `PrefixReader` correctly consumes `body_prefix` before socket reads.
- `read_chunked_http_response_body()` returns raw chunked wire bytes without duplication.
- `read_http_response_sequence()` consumes 1xx responses until a final response and rejects 101.
- raw chunked responses skip entity transforms.
- HTTP/1.1 close-delimited responses require `Connection: close`.
- `spawn_auxiliary_task()` uses:
  - `auxiliary_submission_lock`;
  - a one-shot start gate;
  - registry insertion before gate release;
  - stale-task abort-and-await;
  - capacity checks before user-future execution.
- `AuxiliaryRegistryEntry::{Reserved, Running}` exists, although the production submission path currently inserts `Running` directly.
- shutdown and recovery drain `auxiliary_tasks`, but do not currently coordinate with `auxiliary_submission_lock`.
- the HTTP framing suite reports 60 passing tests locally.

Known remaining defects:

- a partial final response head in informational-response leftover bytes is discarded;
- close-delimited reads can continue indefinitely if bytes arrive just before each idle timeout;
- trailers are bounded only by the broader body limit;
- status parsing accepts arbitrary numeric `u16` values and duplicates parsing logic;
- shutdown can race a new auxiliary registration;
- race tests still mostly simulate internals.

---

## Non-Goals

Do not enable worker-level mesh supervision in this iteration.

Do not redesign the proxy around Hyper.

Do not add HTTP/2 or HTTP/3 backend support.

Do not add request pipelining, WebSocket, `CONNECT`, or bidirectional tunneling.

Do not refactor unrelated mesh topology, DHT, Raft, threat-intel, or worker code.

Do not expand the auxiliary system into a general scheduler.

---

# Part A — Preserve Partial Final Response Heads

## Phase 1 — Remove The Split Parsing Paths

`read_http_response_sequence()` currently has:

- one parser path for bytes already in `leftover`;
- another parser path through `read_http_response_head()` for socket reads.

This duplication is the source of partial-leftover loss and parser drift.

Replace both with one persistent buffered framing path.

Preferred design:

```rust
struct HttpResponseSequenceReader<'a, R> {
    reader: &'a mut R,
    buffered: Vec<u8>,
}
```

or reuse `PrefixReader`:

```rust
let mut prefixed = PrefixReader::new(leftover, reader);
let head = read_http_response_head(&mut prefixed, ...).await?;
```

The implementation must preserve any unread bytes after parsing the head for the next informational/final response.

Because the existing `PrefixReader` consumes bytes but does not expose remaining prefix/socket bytes, the cleanest implementation is likely a persistent `Vec<u8>` buffer owned by `read_http_response_sequence()`.

## Phase 2 — Add A Buffer-Oriented Head Parser

Extract a pure parser:

```rust
fn try_parse_http_response_head(
    buffer: &[u8],
    max_header_bytes: usize,
) -> Result<Option<(FramedHttpResponseHead, usize)>, HttpResponseFramingError>
```

Semantics:

- `Ok(None)` when `\r\n\r\n` is not yet present;
- `Ok(Some((head, consumed)))` when a complete head is available;
- `consumed` is the index immediately after the header terminator;
- `head.body_prefix` should contain bytes after the head only when returning the final response to the body framer;
- informational response processing should retain all bytes after `consumed` in the sequence buffer.

This parser should become the only response-head parser.

## Phase 3 — Rewrite `read_http_response_head()` Around The Pure Parser

`read_http_response_head()` should:

1. maintain a local buffer;
2. call `try_parse_http_response_head()` after every read;
3. enforce remaining-capacity reads;
4. enforce idle and total deadlines;
5. return the parsed head with any coalesced body prefix.

Do not duplicate status/version/header framing logic elsewhere.

## Phase 4 — Rewrite `read_http_response_sequence()` With One Persistent Buffer

Required algorithm:

```rust
let deadline = Instant::now() + total_timeout;
let mut buffer = Vec::new();

loop {
    if let Some((head, consumed)) = try_parse_http_response_head(&buffer, max_header_bytes)? {
        if head.status_code == 101 {
            return Err(...);
        }

        let remainder = buffer.split_off(consumed);

        if head.status_code >= 200 {
            return Ok(head.with_body_prefix(remainder));
        }

        buffer = remainder;
        continue;
    }

    read_more_into_buffer(...).await?;
}
```

Important details:

- partial final heads remain in `buffer` until completed;
- multiple informational responses in one read are handled;
- an informational response followed by a partial final head is handled;
- a final response plus body prefix is preserved;
- the total sequence deadline is shared across all informational responses.

## Phase 5 — Add Exhaustive Informational Boundary Tests

Use production `read_http_response_sequence()`.

Required cases:

- `100 Continue` followed by a final head split at every byte boundary;
- `103 Early Hints` followed by a final head split at every byte boundary;
- multiple 1xx responses followed by final head;
- informational and final heads fully coalesced;
- informational terminator plus one byte of final head in leftover;
- informational terminator plus partial status token;
- informational terminator plus partial header name/value;
- final header terminator plus body prefix;
- backend EOF while final head remains partial;
- total sequence deadline across many informational responses.

The byte-boundary test can loop over every split position in one test.

---

# Part B — Add A Total Deadline To Close-Delimited Bodies

## Phase 6 — Extract `read_close_delimited_http_response_body()`

Move the inline close-delimited loop out of `handle_http_proxy_stream()`:

```rust
async fn read_close_delimited_http_response_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Vec<u8>,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpResponseFramingError>
```

Required behavior:

- include prefix bytes in size accounting;
- reject prefix already above limit;
- establish one total deadline;
- each read uses `min(idle_timeout, remaining_total)`;
- EOF terminates successfully;
- idle expiry returns a timeout error;
- total deadline expiry returns a distinct or stable timeout error;
- body-limit overflow returns an error, never truncated output.

## Phase 7 — Use The Existing Body Total Timeout

Use:

```rust
peer_http_response_body_total_timeout_secs
```

Do not introduce another close-delimited timeout field.

## Phase 8 — Add Slow-Drip Close-Delimited Tests

Required cases:

- HTTP/1.0 close-delimited body completes normally;
- HTTP/1.1 `Connection: close` completes normally;
- backend sends one byte before each idle timeout but exceeds total deadline;
- prefix alone exceeds body limit;
- cumulative body exceeds limit;
- idle timeout expires before total deadline;
- EOF exactly at body limit succeeds.

Use the production helper with `tokio::io::duplex()`.

---

# Part C — Enforce Trailer Limits Independently

## Phase 9 — Track Trailer Bytes Separately

After parsing the zero-size chunk, initialize:

```rust
let mut trailer_bytes = 0usize;
```

For every trailer byte consumed:

```rust
trailer_bytes += 1;
if trailer_bytes > max_trailer_bytes {
    return Err(HttpResponseFramingError::TrailerTooLarge {
        limit: max_trailer_bytes,
        observed: trailer_bytes,
    });
}
```

Continue counting those bytes toward total wire/body limits if that remains the chosen semantics.

## Phase 10 — Add A Specific Trailer Error

Prefer:

```rust
enum HttpResponseFramingError {
    ...
    TrailerTooLarge { limit: usize, observed: usize },
}
```

Do not report trailer overflow as generic malformed chunking or body overflow.

## Phase 11 — Clarify Limit Semantics

Document:

- `max_peer_http_response_body_bytes` bounds the raw chunked wire body or decoded entity size—choose one and keep existing behavior consistent;
- `max_peer_http_response_trailer_bytes` independently bounds all bytes after the zero chunk through the terminating empty line.

For this pass, retain raw wire-body accounting and add an independent trailer cap.

## Phase 12 — Add Trailer Tests

Required cases:

- empty trailer accepted;
- exact trailer limit accepted;
- limit + 1 rejected;
- multiple trailer fields counted cumulatively;
- trailer terminator split across prefix/socket boundary;
- oversized trailer entirely in body prefix;
- oversized trailer arriving slowly still bounded by total deadline.

---

# Part D — Centralize Strict Response-Head Parsing

## Phase 13 — Add A Strict Status-Line Parser

Extract:

```rust
fn parse_http_response_status_line(
    line: &str,
) -> Result<(HttpVersion, u16), HttpResponseFramingError>
```

Required validation:

- exactly three whitespace-separated semantic parts are not required because reason phrase may be empty or contain spaces;
- version token must be exactly `HTTP/1.0` or `HTTP/1.1`;
- status token length must be exactly 3;
- every status byte must be ASCII digit;
- status must be in `100..=599`;
- malformed control characters rejected.

Suggested implementation:

```rust
let mut parts = line.splitn(3, ' ');
let version = parts.next().ok_or(...)?;
let status = parts.next().ok_or(...)?;
```

Handle multiple spaces conservatively using `split_whitespace()` only if reason-phrase preservation is irrelevant.

## Phase 14 — Use One Header Parser Everywhere

Both:

- `read_http_response_head()`;
- `read_http_response_sequence()`

must call the same pure head parser.

Delete the duplicated synchronous leftover parsing block.

## Phase 15 — Parse Header Names Exactly

`parse_http_response_framing()` currently uses lowercased `starts_with()` checks.

Replace with exact header-name splitting:

```rust
let (name, value) = line.split_once(':').ok_or(...)?;
```

Then compare names case-insensitively.

This prevents accidental matching of malformed names such as:

```text
Content-Length-Extra:
```

Required handling:

- duplicate equal `Content-Length` accepted or rejected according to existing policy;
- conflicting duplicates rejected;
- comma-separated `Connection` tokens parsed case-insensitively;
- unsupported transfer encodings rejected;
- `Transfer-Encoding: gzip, chunked` either rejected or explicitly parsed according to policy; preferred narrow behavior: reject anything except a single final `chunked` token.

## Phase 16 — Add Strict Parser Tests

Required status cases:

- valid 100, 200, 599;
- invalid 99, 600, 1000;
- non-digit token;
- two-digit/four-digit token;
- unsupported HTTP version;
- missing status;
- empty reason phrase accepted if valid syntax.

Required header-name cases:

- mixed-case valid names;
- malformed no-colon line;
- `Content-Length-Extra` does not match;
- duplicate equal/conflicting lengths;
- tokenized `Connection: keep-alive, Close`;
- unsupported transfer coding list.

---

# Part E — Serialize Auxiliary Submission With Cleanup

## Phase 17 — Define Submission Eligibility By Lifecycle State

`spawn_auxiliary_task()` must reject new work when the transport is:

- `Stopping`;
- `Stopped`;
- `Failed`, unless an explicitly documented recovery-internal task kind is allowed.

Allowed states:

- `Running`;
- `Starting` only for task kinds explicitly required during startup.

Preferred helper:

```rust
fn auxiliary_submission_allowed(
    state: MeshTransportState,
    kind: AuxiliaryTaskKind,
) -> bool
```

For current task kinds:

- `PreflightRoute`: allowed in `Starting` or `Running` as appropriate;
- `EdgeReplicaRefresh`: allowed only in `Running`.

## Phase 18 — Acquire Submission Lock Before Cleanup Drains

In normal shutdown and failed-state recovery:

1. transition lifecycle state / publish shutdown intent first;
2. acquire `auxiliary_submission_lock`;
3. drain, abort, and await all auxiliary entries;
4. keep the lock until the registry is verified empty;
5. release only after no new submission can be accepted due to lifecycle state.

Startup rollback should follow the same rule if steady-state auxiliary submission can race it.

The lock ordering must be documented to avoid deadlocks:

```text
lifecycle operation lock
  -> auxiliary_submission_lock
    -> auxiliary_tasks lock
```

Never acquire them in reverse order.

## Phase 19 — Recheck State Under Submission Lock

`spawn_auxiliary_task()` should:

1. acquire `auxiliary_submission_lock`;
2. read/check lifecycle state;
3. reject if cleanup has begun;
4. perform dedup/capacity;
5. insert ownership record;
6. release start gate;
7. release submission lock.

Do not check lifecycle state before acquiring the lock and then rely on a stale result.

## Phase 20 — Finalize Gated Tasks On Rejection

For state or capacity rejection:

- drop `start_tx`;
- await the gated task to return `Cancelled` without requiring `abort()` if it can exit immediately;
- use abort-and-await only as fallback if the gated wrapper does not finish within a tiny bounded interval;
- no completion event should be published for an unregistered task unless the reaper explicitly tolerates it.

Preferred simplification:

- do not spawn until state/dedup/capacity checks pass;
- then create gated handle, insert, and open gate while still under the submission lock.

Because the lock serializes submissions, the task ID and entry can be prepared after checks without a reservation race.

## Phase 21 — Decide Whether `Reserved` Is Still Needed

The current production path inserts `Running` directly before opening the gate.

Choose one:

### Preferred Simplification

Remove `Reserved` if no production path uses it and the gated `Running` entry fully represents ownership.

### Alternative

Use `Reserved` during submission and convert to `Running` atomically.

Do not retain an unused variant solely because the plan once proposed it.

Update docs and tests accordingly.

## Phase 22 — Add Real Submission/Cleanup Race Tests

Create a minimal real `MeshTransport` test fixture and call production `spawn_auxiliary_task()`.

Required cases:

### Immediate Completion Through Production Path

- submit a future that returns immediately;
- assert registry entry is installed before completion processing;
- wait for auxiliary reaper;
- registry returns to zero.

### Concurrent Duplicate Production Submissions

- submit two same-key edge refreshes concurrently;
- assert at most one user future executes at a time;
- stale task is aborted and awaited;
- final registry contains at most one matching entry;
- completion reaps to zero.

### Capacity Boundary Through Production Path

- submit more than capacity concurrently;
- assert executed-future counter never exceeds capacity;
- rejected futures never execute;
- registry never exceeds capacity;
- all accepted tasks can be finalized.

### Shutdown Versus Submission

- hold a submission at a test hook before insertion;
- begin shutdown;
- assert either:
  - submission completes registration and shutdown drains it; or
  - submission is rejected before user future execution;
- no task appears after shutdown’s auxiliary verification.

### Recovery Versus Submission

Repeat for `recover_failed_state()` or the internal cleanup helper.

## Phase 23 — Add Test Hooks Without Public API Expansion

Use one of:

- `#[cfg(test)]` barriers inside the transport;
- module-local tests with private field access;
- a crate-private test fixture.

Do not add new public production adapters.

---

# Part F — Cleanup Verification And Diagnostics

## Phase 24 — Verify Registry State Under Submission Exclusion

Successful shutdown/recovery verification should assert, while holding `auxiliary_submission_lock`:

- no `Running` entries;
- no `Reserved` entries if retained;
- no gated tasks pending;
- auxiliary reaper/top-level task state consistent.

## Phase 25 — Improve Rejection Diagnostics

Differentiate auxiliary submission rejection reasons:

```rust
enum AuxiliarySpawnError {
    LifecycleNotRunning(MeshTransportState),
    CapacityExceeded,
    DedupReplaced,
    ShutdownInProgress,
}
```

`DedupReplaced` may not need to be an error if replacement is successful.

At minimum, avoid returning bare `Err(())` internally where diagnostics matter.

Keep metrics low-cardinality.

## Phase 26 — Audit Lock Ordering

Document and test the lock order involving:

- lifecycle operation lock;
- `auxiliary_submission_lock`;
- `auxiliary_tasks` registry lock;
- task-group/session locks where relevant.

Add comments at cleanup and submission entry points.

No code should hold `auxiliary_tasks` and then await `auxiliary_submission_lock`.

---

# Part G — File-Level Implementation Guide

## `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Implement:

- pure buffered response-head parser;
- persistent sequence buffer;
- partial informational-head preservation;
- strict shared status/version/header parsing;
- extracted close-delimited body reader with total deadline;
- independent trailer-size accounting;
- focused module tests.

## `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- lifecycle-state gating for auxiliary submissions;
- submission-lock coordination with shutdown/recovery/rollback;
- real production-path race tests;
- optional removal or real use of `AuxiliaryRegistryEntry::Reserved`;
- typed auxiliary spawn errors if practical.

## `crates/synvoid-mesh/src/mesh/lifecycle.rs`

Update:

- auxiliary registry enum if simplifying/removing `Reserved`;
- auxiliary spawn error type if shared;
- no new public API.

## Tests

Update/add:

- `tests/mesh_http_framing.rs` for public/generic framing behavior;
- module-local `transport_peer.rs` tests for pure parsers;
- module-local `transport.rs` tests for production auxiliary races;
- `tests/mesh_task_ownership_guard.rs` for cleanup/submission serialization guardrails.

---

# Part H — Ordered Execution Sequence

A smaller model should implement in this exact order:

1. Extract strict pure response-head parser.
2. Refactor `read_http_response_head()` to use it.
3. Refactor `read_http_response_sequence()` to maintain one persistent buffer.
4. Add exhaustive partial-final-head tests.
5. Extract close-delimited body reader and add total deadline.
6. Add independent trailer byte accounting and error variant.
7. Add close-delimited and trailer tests.
8. Add lifecycle-state auxiliary submission check under `auxiliary_submission_lock`.
9. Acquire submission lock during shutdown/recovery auxiliary drain.
10. Decide/remove/use `Reserved` consistently.
11. Add production-path auxiliary race tests with private test hooks.
12. Add guardrails and lock-order documentation.
13. Update architecture and skill docs.

Do not begin worker-level mesh supervision until this pass is complete.

---

# Part I — Guardrails

Update `tests/mesh_task_ownership_guard.rs` to assert:

- shutdown/recovery acquire `auxiliary_submission_lock` before auxiliary drain;
- `spawn_auxiliary_task()` checks lifecycle state while holding the submission lock;
- successful cleanup verifies no `Reserved` or `Running` auxiliary entries;
- `read_http_response_sequence()` no longer contains a separate manual leftover status parser;
- partial leftover bytes feed the same response-head parser as socket bytes;
- close-delimited reads use total body timeout;
- trailer bytes have a separate limit check;
- one shared status-line parser validates exact version and three-digit range.

Behavioral tests remain authoritative.

---

# Part J — Documentation

Update:

- `architecture/mesh_transport_lifecycle.md`;
- `architecture/mesh.md`;
- `skills/synvoid_mesh.md`;
- `AGENTS.md`;
- `crates/synvoid-mesh/AGENTS.override.md` if present.

Document:

- persistent buffered response-sequence parsing;
- partial informational/final-head preservation;
- idle plus total deadlines for every body mode;
- independent chunked trailer limits;
- strict shared response status/header parsing;
- auxiliary submission exclusion during shutdown/recovery;
- production-path race coverage;
- mesh transport/lifecycle subsystem considered closed after acceptance criteria pass;
- worker-level mesh supervision is the next target.

Remove outdated claims that hand-built gate/map tests alone prove production auxiliary atomicity.

---

# Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-mesh --features mesh http
cargo test -p synvoid-mesh --features mesh auxiliary
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test --test mesh_http_framing --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test mesh_forced_cleanup --features mesh,dns
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

If lifecycle or registry types affect workspace callers:

```bash
cargo test --workspace --no-run
```

Record known certificate-test failures separately and confirm they reproduce at the base commit before classifying them as pre-existing.

---

# Acceptance Criteria

The mesh transport/lifecycle subsystem is complete only when all of the following are true:

1. Partial final response heads after informational responses are preserved across reads.
2. Informational/final response parsing uses one shared buffered parser.
3. Every split position between informational and final responses is covered by production-helper tests.
4. Close-delimited bodies enforce both idle and total deadlines.
5. Close-delimited overflow returns an error rather than truncated output.
6. Chunked trailers are independently bounded by `max_peer_http_response_trailer_bytes`.
7. Response versions and status codes are strictly validated by one shared parser.
8. Header names are parsed exactly rather than by prefix matching.
9. Auxiliary submissions are rejected after shutdown/recovery intent begins.
10. Shutdown, recovery, and rollback exclude new auxiliary registration while draining and verifying the registry.
11. No auxiliary entry can be inserted after successful cleanup verification.
12. Production-path tests exercise immediate completion, deduplication, capacity, shutdown race, and recovery race.
13. Rejected auxiliary futures do not execute.
14. No auxiliary handle, reservation, stream handler, session, connection, response framer, or runtime resource survives successful cleanup.
15. `AuxiliaryRegistryEntry::Reserved` is either used consistently or removed.
16. Existing ownership, blocklist, threat-intel, provenance, mesh-ID, composition, and lifecycle guardrails remain green.
17. Documentation marks mesh transport/lifecycle as closed and identifies worker-level mesh supervision as the next architectural target.

---

## Notes For The Implementer

This is a closure pass, not a redesign.

Keep the changes local and testable.

The two most important implementation rules are:

> Keep one persistent byte buffer across an HTTP response sequence.

> Once cleanup intent begins, no new auxiliary task may cross the ownership boundary.
