# Mesh Transport Nested-Cleanup Corrective Pass — Iteration 77

## Purpose

Iteration 76 corrected zero-budget top-level task cleanup, introduced cooperative peer-session cancellation, made DHT force restoration fail closed on full-bucket conflicts, documented logical DHT snapshot semantics, and split stream timeout configuration into framing/read and optional total-lifetime controls.

The review of `8b437b399ce421e773622fb97bb06315e8b0ca7e` found seven remaining defects:

1. `drain_peer_stream_handlers()` computes a deadline but waits on `JoinSet::join_next().await` without a deadline-aware `select` or `timeout`, so one hung stream handler can block session finalization indefinitely.
2. `apply_read_timeouts()` still wraps the complete `handle_peer_message()` future, so the configured “read/framing” timeout remains a total handler lifetime timeout even when `peer_stream_total_timeout_secs` is disabled.
3. The zero-budget branch of `stop_peer_session_task()` forcibly aborts the parent but usually returns `Failed("parent cancelled")` instead of `ForcedParentAbort`.
4. Rollback only records `ForcedParentAbort` as incomplete cleanup and silently ignores `PeerSessionStopOutcome::Failed`.
5. `recover_failed_state()` accumulates `session_errors` but never merges them into final recovery verification, allowing a transition to `Stopped` despite unproven nested cleanup.
6. The new forced-cleanup tests model small helper futures and enum variants rather than exercising the real nested session/stream cleanup paths.
7. `start_datagram_handler()` still launches each incoming datagram handler with bare `tokio::spawn()`, leaving another mesh-owned task tree outside lifecycle ownership.

This pass should correct nested cleanup semantics, make read timeout placement truthful, and close the last visible detached mesh task path.

The primary invariant is:

> A parent lifecycle task may report completion only after every nested child task has either completed or been aborted and awaited. Timeout names must describe the operation actually bounded, and every failed or forced cleanup outcome must prevent a false clean lifecycle transition.

---

## Current Known State

At `8b437b399ce421e773622fb97bb06315e8b0ca7e`:

- `MeshTaskGroup::join_all(Duration::ZERO)` aborts and awaits all retained top-level tasks.
- `rollback_startup()` always calls `stage.task_group.join_all(remaining(deadline))`.
- `PeerSessionTask` contains `shutdown_tx: watch::Sender<bool>`.
- `peer_message_loop()` selects on cooperative shutdown and owns per-stream handlers in a session-local `JoinSet`.
- `stop_peer_session_task()` attempts cooperative parent completion, then aborts and awaits the parent.
- DHT force restoration no longer evicts unrelated contacts when the target is absent from a full bucket.
- `peer_message_timeout_secs` and `peer_stream_total_timeout_secs` are distinct config fields.
- `start_datagram_handler()` owns the outer listener loop but not the tasks spawned for each decoded datagram.

Known remaining defects:

- child stream drain deadline is not enforced while waiting for `join_next()`;
- read timeout wraps the full handler future;
- immediate forced parent abort is misclassified;
- failed parent cleanup outcomes are not consistently added to rollback/recovery errors;
- recovery drops `session_errors`;
- tests do not execute real nested ownership paths;
- datagram child tasks remain detached and unbounded.

---

## Non-Goals

Do not enable worker-level mesh supervision.

Do not redesign DHT/Raft responsibilities.

Do not change peer authentication, TLS, blocklist, threat-intel, or membership semantics.

Do not redesign the mesh protocol or message wire format.

Do not introduce general task restart policy.

Do not refactor all message handlers; limit changes to ownership and read-boundary timeout placement.

---

# Part A — Make Stream-Handler Drain Truly Deadline-Aware

## Phase 1 — Replace Unbounded `join_next().await`

In `crates/synvoid-mesh/src/mesh/transport_peer.rs`, rewrite `drain_peer_stream_handlers()` so no cooperative wait can exceed the supplied timeout.

Current unsafe pattern:

```rust
while let Some(result) = handlers.join_next().await {
    classify(result);
    if Instant::now() >= deadline {
        break;
    }
}
```

Required pattern:

```rust
let deadline = tokio::time::Instant::now() + timeout;

while !handlers.is_empty() {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    if left.is_zero() {
        break;
    }

    match tokio::time::timeout(left, handlers.join_next()).await {
        Ok(Some(result)) => classify_stream_join(result, &mut report),
        Ok(None) => break,
        Err(_) => break,
    }
}

let forced = handlers.len();
if forced > 0 {
    handlers.abort_all();
    while let Some(result) = handlers.join_next().await {
        classify_forced_stream_join(result, &mut report);
    }
}
```

Required behavior:

- a single hung handler cannot prevent the deadline from being observed;
- every remaining handler is aborted after cooperative timeout;
- every aborted handler is awaited before return;
- the returned `PeerStreamDrainReport` accounts for every handler present at finalization.

## Phase 2 — Centralize Stream Join Classification

Add small private helpers:

```rust
fn classify_stream_join(
    result: Result<Result<(), MeshTransportError>, JoinError>,
    report: &mut PeerStreamDrainReport,
)
```

and, if useful:

```rust
fn classify_forced_stream_join(...)
```

Classification:

- `Ok(Ok(()))` -> `drained += 1`;
- `Ok(Err(_))` -> `failed += 1`;
- `Err(e) if e.is_panic()` -> `failed += 1`;
- `Err(e) if e.is_cancelled()` after explicit `abort_all()` -> `aborted += 1`;
- unexpected cancellation before explicit abort -> `failed += 1`.

Do not count every post-abort join result blindly as aborted without checking whether the task had already failed or panicked.

## Phase 3 — Make Drain Budget Configurable

Replace the hardcoded five-second value in `peer_message_loop()` with a config field or an existing lifecycle timeout.

Suggested field:

```rust
pub peer_stream_drain_timeout_secs: u64
```

Default: 5 seconds.

Add it to:

- `crates/synvoid-mesh/src/mesh/config.rs`;
- `crates/synvoid-config/src/mesh.rs`;
- serde/default/documentation paths.

A separate drain timeout is clearer than reusing framing or total stream timeout.

## Phase 4 — Preserve One Finalization Path

Keep every `peer_message_loop()` exit path flowing through:

1. stop accepting streams;
2. call deadline-aware `drain_peer_stream_handlers()`;
3. update final topology status;
4. return `PeerSessionExit`.

Do not add direct returns inside the select loop.

---

# Part B — Put Read Timeouts On Actual Read Operations

## Phase 5 — Remove `apply_read_timeouts()` Around The Full Handler

Delete or repurpose the helper that currently does:

```rust
timeout(read_timeout, handle_peer_message(...))
```

The full handler must only be wrapped by `peer_stream_total_timeout_secs` when that optional setting is enabled.

Required spawn logic:

```rust
stream_handlers.spawn(async move {
    let handler = transport.handle_peer_message(
        &mut send_stream,
        &mut recv_stream,
        &topo,
        pid,
        read_timeout,
    );

    if let Some(total) = total_timeout {
        timeout(total, handler)
            .await
            .unwrap_or(Err(MeshTransportError::Timeout))
    } else {
        handler.await
    }
});
```

## Phase 6 — Pass Read Timeout Into `handle_peer_message()`

Change the signature:

```rust
pub(crate) async fn handle_peer_message(
    &self,
    send_stream: &mut SendStream,
    recv_stream: &mut RecvStream,
    topology: &MeshTopology,
    peer_node_id: String,
    read_timeout: Duration,
) -> Result<(), MeshTransportError>
```

Thread the timeout only into read/framing operations.

## Phase 7 — Add Read Helpers

Add focused helpers such as:

```rust
async fn read_exact_with_timeout(
    recv: &mut RecvStream,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), MeshTransportError>
```

```rust
async fn read_to_end_with_timeout(
    recv: &mut RecvStream,
    max_len: usize,
    timeout: Duration,
) -> Result<Vec<u8>, MeshTransportError>
```

```rust
async fn read_http_headers_with_timeout(
    recv: &mut RecvStream,
    first_byte: u8,
    timeout: Duration,
    max_header_bytes: usize,
) -> Result<Vec<u8>, MeshTransportError>
```

Map timeout expiry to `MeshTransportError::Timeout`.

## Phase 8 — Bound HTTP Framing Correctly

Current HTTP handling calls `BufReader::read_to_string()`, which reads until EOF and conflates framing with total body lifetime.

Replace it with bounded header framing:

- stop at `\r\n\r\n`;
- cap total header bytes;
- apply read timeout to each framing read or one idle timeout around the header parse;
- do not wait for peer EOF to identify the end of headers.

Suggested constant/config:

```rust
pub max_peer_http_header_bytes: usize
```

Use existing HTTP header limits if already available.

## Phase 9 — Audit Non-HTTP Message Reads

Apply read-boundary timeout to:

- first-byte discriminator;
- message length prefix;
- fixed-size metadata reads;
- payload body reads;
- snapshot frame reads;
- any loop waiting for additional framed mesh data.

Do not wrap CPU work, Raft client writes, DHT operations, proxy execution, response transforms, or send operations with the read timeout.

## Phase 10 — Preserve Optional Total Lifetime Timeout

When `peer_stream_total_timeout_secs > 0`, it may wrap the complete handler.

When it is zero:

- no total handler deadline exists;
- read stalls remain bounded;
- explicit session shutdown remains capable of aborting the handler through the parent `JoinSet`.

Document this distinction precisely.

---

# Part C — Correct Parent-Session Stop Classification

## Phase 11 — Make Forced Abort Return `ForcedParentAbort`

In `stop_peer_session_task()`, change the zero-budget branch.

Required semantics:

```rust
handle.abort();
let join = handle.await;

match join {
    Err(err) if err.is_panic() => PeerSessionStopOutcome::Failed(
        format!("peer-session parent panicked during forced abort: {err}")
    ),
    _ => PeerSessionStopOutcome::ForcedParentAbort,
}
```

A cancelled `JoinError` is the expected result of `abort()` and must not be mapped to generic `Failed("parent cancelled")`.

The timeout-expired branch should use the same helper to prevent divergence.

## Phase 12 — Add One `force_abort_peer_session()` Helper

Suggested:

```rust
async fn force_abort_peer_session(
    mut handle: JoinHandle<()>,
) -> PeerSessionStopOutcome
```

Use it for:

- zero-budget path;
- cooperative timeout path.

This ensures forced abort classification is identical in both cases.

## Phase 13 — Propagate Every Non-Drained Outcome

Update all callers to match exhaustively:

```rust
match outcome {
    PeerSessionStopOutcome::Drained(_) => {}
    PeerSessionStopOutcome::ForcedParentAbort => {
        errors.push(...);
    }
    PeerSessionStopOutcome::Failed(error) => {
        errors.push(...);
    }
}
```

Apply to:

- `stop_staged_peer_activity()`;
- `recover_failed_state()`;
- `shutdown_with_timeout()` report construction.

Rollback must not remain clean after either `ForcedParentAbort` or `Failed`.

Recovery must not transition to `Stopped` after either outcome.

Normal shutdown may return `Stopped`, but must report these outcomes accurately as aborted/failed sessions and should not describe the shutdown as fully clean.

## Phase 14 — Add Context-Rich Errors

Include:

- session ID;
- node ID where available;
- generation;
- whether failure occurred during rollback, recovery, or normal shutdown;
- underlying reason.

Avoid generic repeated strings like `parent cancelled` without identity.

---

# Part D — Fix Recovery Error Aggregation

## Phase 15 — Merge `session_errors` Into Final Verification

In `recover_failed_state()`, change:

```rust
let mut issues = Vec::new();
issues.extend(remaining_errors);
```

into:

```rust
let mut issues = Vec::new();
issues.extend(session_errors);
issues.extend(remaining_errors);
```

Deduplicate if necessary.

## Phase 16 — Record `Failed` Session Outcomes

The recovery loop currently records only `ForcedParentAbort`.

Required match:

```rust
match outcome {
    PeerSessionStopOutcome::Drained(_) => {}
    PeerSessionStopOutcome::ForcedParentAbort => session_errors.push(...),
    PeerSessionStopOutcome::Failed(error) => session_errors.push(...),
}
```

## Phase 17 — Preserve Failed-State Residue/Diagnostics

If recovery fails only because a parent session required forced abort or failed join:

- lifecycle remains `Failed`;
- returned error contains the session cleanup issue;
- recovery diagnostics remain available;
- a subsequent explicit recovery may retry verification.

If no peer residue exists, retain a general failed-cleanup diagnostic field or include the issue in the returned error and lifecycle state. Do not clear all evidence and then return `Failed` without context.

## Phase 18 — Verify Reaper/Registry State After Session Errors

Even after forced parent abort, check:

- session registry empty;
- no session-bound auxiliary tasks remain;
- connection removed;
- top-level task group empty.

These checks do not prove child stream `JoinSet` finalization after parent abort, so the recorded session error must still keep recovery incomplete.

---

# Part E — Own Datagram Handler Tasks

## Phase 19 — Replace Bare Datagram `tokio::spawn()`

In `start_datagram_handler()`, introduce a local child `JoinSet`:

```rust
let mut handlers: JoinSet<Result<(), MeshTransportError>> = JoinSet::new();
```

Replace:

```rust
tokio::spawn(async move { ... });
```

with:

```rust
handlers.spawn(async move {
    transport.handle_incoming_datagram(&peer_id, data).await
});
```

## Phase 20 — Bound Datagram Handler Concurrency

Add a configured limit:

```rust
pub max_concurrent_datagram_handlers: usize
```

Use either:

- `JoinSet::len()` and reject/drop datagrams at capacity; or
- a semaphore.

Default should be conservative but adequate for expected gossip/load-report traffic.

When at capacity:

- drop the datagram;
- increment a low-cardinality metric;
- log at trace/debug with rate limiting.

Do not create an unbounded pending queue.

## Phase 21 — Reap Completed Datagram Handlers

Add a `tokio::select!` branch:

```rust
Some(result) = handlers.join_next(), if !handlers.is_empty() => {
    classify_datagram_handler_exit(result);
}
```

Classification:

- clean completion;
- handler error;
- panic;
- cancellation during service shutdown.

## Phase 22 — Drain On Datagram Service Shutdown

When outer shutdown signal arrives:

1. stop reading new datagrams;
2. cooperatively wait for active handlers until a configured/local drain deadline;
3. abort remaining handlers;
4. await every aborted handler;
5. return from `start_datagram_handler()` only after the `JoinSet` is empty.

Suggested helper:

```rust
async fn drain_datagram_handlers(
    handlers: &mut JoinSet<Result<(), MeshTransportError>>,
    timeout: Duration,
) -> DatagramDrainReport
```

Use the same deadline-aware pattern as stream-handler drain.

## Phase 23 — Add Datagram Handler Timeout Policy

Most datagram handlers should be bounded one-shot operations, but some may perform Raft writes, blocklist snapshot generation, or DHT work.

Add an optional total datagram-handler timeout only if needed:

```rust
pub datagram_handler_timeout_secs: u64
```

Otherwise rely on outer shutdown abort-and-await.

Do not reuse stream framing timeout.

## Phase 24 — Audit Nested Spawns In Datagram Paths

Search `handle_incoming_datagram()` and direct helper calls for additional `tokio::spawn()` calls.

Any nested task must be:

- awaited inline; or
- registered in the same datagram handler ownership tree; or
- explicitly assigned to another transport-owned registry.

---

# Part F — Real Behavioral Tests

## Phase 25 — Add Real Stream Drain Deadline Test

Add to `tests/mesh_forced_cleanup.rs` or a new internal unit-test module with access to the helper:

1. Create a `JoinSet` containing one task that never completes and has a drop guard.
2. Call `drain_peer_stream_handlers()` with a short timeout.
3. Assert function returns near the timeout rather than hanging.
4. Assert `report.aborted == 1`.
5. Assert drop guard fired before return.
6. Assert `JoinSet` is empty.

Do not model this with a separate toy future.

## Phase 26 — Add Zero-Budget Parent Abort Classification Test

Exercise the real `stop_peer_session_task()` helper, not only enum construction.

1. Spawn a parent task that never returns.
2. Call helper with `Duration::ZERO`.
3. Assert outcome is `ForcedParentAbort`.
4. Assert parent drop guard fired before helper returned.

Add a panic variant to prove panic maps to `Failed`.

## Phase 27 — Add Rollback Error Propagation Test

Use test hooks or a directly constructible staged peer session:

1. Force zero remaining budget.
2. Require parent abort.
3. Run rollback.
4. Assert `RollbackReport.clean == false`.
5. Assert error contains session identity and forced parent abort.
6. Assert lifecycle becomes `Failed` through `rollback_and_return()`.

## Phase 28 — Add Recovery Error Aggregation Test

1. Put transport into `Failed` with one session requiring parent abort.
2. Call `recover_failed_state(Duration::ZERO)`.
3. Assert returned error contains session cleanup failure.
4. Assert lifecycle remains `Failed`.
5. Assert it does not transition to `Stopped` merely because registries are empty.

## Phase 29 — Add True Read-Timeout Test

Use a test stream or helper abstraction.

Required cases:

### Framing Stall

- first-byte or length read stalls;
- read timeout expires;
- handler returns `MeshTransportError::Timeout`.

### Long-Lived Post-Framing Work

- framing completes quickly;
- downstream operation exceeds `peer_message_timeout_secs`;
- `peer_stream_total_timeout_secs == 0`;
- operation remains alive until explicit cancellation/completion.

### Optional Total Timeout

- total timeout configured;
- long-lived operation is terminated at that bound.

## Phase 30 — Add Real Datagram Ownership Test

1. Start datagram handler service with one handler that blocks and has a drop guard.
2. Trigger outer shutdown.
3. Assert handler is drained or aborted and awaited.
4. Assert drop guard fires before outer service returns.
5. Assert no child handle survives.

## Phase 31 — Add Datagram Capacity Test

1. Fill handler capacity with blocking tasks.
2. Deliver one additional datagram.
3. Assert no additional task is spawned.
4. Assert drop/rejection metric or counter increments.

---

# Part G — Guardrails

## Phase 32 — Update `tests/mesh_task_ownership_guard.rs`

Add checks that:

- `drain_peer_stream_handlers()` uses `timeout(...)` or `select!` around `join_next()`;
- it does not perform bare `join_next().await` before checking the deadline;
- the read-timeout helper does not wrap the complete `handle_peer_message()` future;
- read timeout appears at actual `RecvStream` read operations;
- zero-budget forced parent abort returns `ForcedParentAbort`;
- all `PeerSessionStopOutcome::Failed` branches are propagated;
- `recover_failed_state()` merges `session_errors` into `issues`;
- `start_datagram_handler()` no longer uses bare `tokio::spawn()` for incoming datagrams;
- datagram handlers are owned by a `JoinSet` and drained before outer return.

## Phase 33 — Add No-Bare-Datagram-Spawn Guard

Reject unreviewed `tokio::spawn()` inside:

- `start_datagram_handler()`;
- `handle_incoming_datagram()`;
- direct datagram helper paths.

Allow only reason-bearing exceptions.

## Phase 34 — Add Timeout Naming Guard

Ensure docs and comments do not call a whole-handler timeout a read/framing timeout.

If a helper wraps the complete handler, it must be named total/lifetime timeout.

---

# Part H — File-Level Implementation Guide

## Phase 35 — `crates/synvoid-mesh/src/mesh/transport_peer.rs`

Implement:

- deadline-aware `drain_peer_stream_handlers()`;
- read timeout at actual read boundaries;
- bounded HTTP header framing;
- optional total stream timeout only around complete handler;
- datagram handler `JoinSet`, capacity, reaping, and shutdown drain.

## Phase 36 — `crates/synvoid-mesh/src/mesh/transport.rs`

Implement:

- forced parent abort classification helper;
- exhaustive handling of `PeerSessionStopOutcome`;
- rollback errors for `Failed` and `ForcedParentAbort`;
- recovery aggregation of `session_errors`;
- shutdown report classification consistency.

## Phase 37 — `crates/synvoid-mesh/src/mesh/config.rs`

Add/default/document:

- `peer_stream_drain_timeout_secs`;
- `max_concurrent_datagram_handlers`;
- optional `datagram_handler_drain_timeout_secs`;
- optional header-size limit if not already available.

## Phase 38 — `crates/synvoid-config/src/mesh.rs`

Mirror the configuration fields and serde defaults.

Preserve backward-compatible defaults.

## Phase 39 — `tests/mesh_forced_cleanup.rs`

Replace toy-only tests with real helper/path tests where access permits.

Keep existing useful top-level `MeshTaskGroup` and DHT conflict tests.

## Phase 40 — Internal Test Visibility

If private helpers prevent realistic integration tests, expose them only under `#[cfg(test)]` or add unit tests in the defining module.

Do not make lifecycle internals public solely for external integration tests.

---

# Part I — Ordered Execution Sequence

A smaller model should implement in this exact order:

1. Fix `drain_peer_stream_handlers()` deadline handling and add direct tests.
2. Add shared stream join classification helpers.
3. Correct zero-budget forced parent abort classification.
4. Propagate all non-drained outcomes into rollback/recovery errors.
5. Merge `session_errors` into recovery verification.
6. Move read timeout to actual read/framing operations.
7. Replace HTTP `read_to_string()` framing with bounded header parsing.
8. Verify optional total stream timeout behavior.
9. Add datagram handler `JoinSet` and capacity limit.
10. Add datagram shutdown drain/abort/await.
11. Add real behavioral tests for nested stream and datagram ownership.
12. Add guardrails.
13. Update documentation.

Do not begin worker-level mesh supervision in this pass.

---

# Verification Commands

Run focused tests:

```bash
cargo test -p synvoid-mesh --features mesh task_group
cargo test -p synvoid-mesh --features mesh transport_peer
cargo test -p synvoid-mesh --features mesh lifecycle
cargo test --test mesh_forced_cleanup --features mesh,dns
cargo test --test mesh_startup_rollback --features mesh,dns
cargo test --test mesh_lifecycle_tests --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
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

If config fields change workspace callers:

```bash
cargo test --workspace --no-run
```

Record known certificate-test failures separately and verify they reproduce on the base commit before classifying them as pre-existing.

---

# Acceptance Criteria

This corrective pass is complete only when all of the following are true:

1. A hung stream handler cannot block `drain_peer_stream_handlers()` beyond its cooperative deadline.
2. Every remaining stream handler is aborted and awaited before peer-session return.
3. `peer_message_timeout_secs` applies only to actual read/framing operations.
4. Valid long-lived post-framing work survives when total stream timeout is disabled.
5. Optional total stream timeout still bounds complete handler lifetime when configured.
6. Zero-budget parent abort returns `ForcedParentAbort`, not generic cancelled failure.
7. Every `ForcedParentAbort` and `Failed` session outcome makes startup rollback incomplete.
8. Recovery merges all session cleanup errors and cannot falsely transition to `Stopped`.
9. Normal shutdown reports drained, aborted, and failed sessions accurately.
10. Incoming datagram handlers are owned, concurrency-bounded, reaped, and drained/aborted-and-awaited on shutdown.
11. No datagram handler, stream handler, peer session, auxiliary task, top-level task, connection, runtime endpoint, topology mutation, or DHT mutation survives successful rollback, shutdown, or recovery.
12. Real behavioral tests exercise hung nested handlers, zero-budget parent abort, recovery error propagation, and datagram child ownership.
13. Worker-level mesh supervision remains accurately documented as deferred.
14. Existing blocklist, threat-intel, provenance, mesh-ID, composition, worker-lifecycle, and mesh-ownership guardrails remain green.

---

## Notes For The Implementer

This is a narrow nested-cleanup pass.

Two rules govern the implementation:

> A deadline must be enforced while waiting, not checked only after the wait returns.

> A timeout named “read” must wrap reads, not the entire request or stream handler.
