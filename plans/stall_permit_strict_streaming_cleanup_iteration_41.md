# Stall Permit Strictness and Streaming Cleanup — Iteration 41

## Purpose

The follow-up that introduced `StallPermit` moved stall concurrency accounting in the right direction: the active stall counter is now released through `Drop`, so task cancellation during a stall sleep no longer leaks a caller-managed `on_stall_end` callback.

One final cleanup pass is needed before closing the HTTP/3/WAF stall section:

1. Make `StallPermit::try_new` a strict atomic acquire instead of load-then-increment.
2. Make the streaming WAF `Stall` path enforce the cap instead of sleeping after `try_new(None)`.
3. Split or clarify stall release vs stall timeout metrics so cancellation is not counted as a completed timeout.
4. Add focused tests for strict cap behavior and streaming-path cap rejection.

This should be a narrow correctness pass. Do not reopen the broader HTTP/3/WAF architecture work.

## Current Known State

Implemented in the prior follow-up:

- `synvoid_metrics::StallPermit` exists.
- `StallPermit::try_new(max_stalled)` returns `None` when `get_active_stalled_requests() >= max_stalled`.
- `Drop for StallPermit` calls `record_stall_end()`.
- HTTP/3 full request WAF dispatch uses `StallPermit::try_new`, returns HTTP/3 `429` on cap, and sleeps only when a permit is acquired.
- HTTP/1/2 full request WAF decision path uses `StallPermit::try_new` and returns `429` on cap.
- Closure plumbing for stall start/end has been removed from the full request and HTTP/3 paths.

Remaining issues:

- `StallPermit::try_new` currently does a load followed by a separate increment. Under concurrent callers, several tasks may observe a below-cap value and increment past the cap.
- `maybe_handle_streaming_waf_decision` obtains `let permit = StallPermit::try_new(...)`, but does not check `None`; it still sleeps and returns timeout even if the cap was reached.
- `record_stall_end()` both decrements active stalled requests and increments `STALL_TIMEOUTS`. With RAII, a cancellation/drop also increments the timeout counter, which makes the metric ambiguous.

## Non-Goals

Do not redesign `WafDecision`.

Do not redesign HTTP/3 WAF dispatch.

Do not add new WAF behavior.

Do not change threat-intel behavior.

Do not move concrete WAF/root services into protocol crates.

Do not create a full metrics subsystem rewrite.

Do not change response format parity except for streaming cap rejection if needed.

## Phase 1 — Make `StallPermit::try_new` Strictly Atomic

Update `crates/synvoid-metrics/src/collection.rs`.

Replace load-then-increment with a compare-and-update operation on `ACTIVE_STALLED_REQUESTS`.

Preferred implementation shape:

```rust
pub fn try_new(max_stalled: u32) -> Option<Self> {
    ACTIVE_STALLED_REQUESTS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if current >= max_stalled as u64 {
                None
            } else {
                Some(current + 1)
            }
        })
        .map(|_| StallPermit { active: true })
        .ok()
        .or_else(|| {
            record_stall_rejected();
            None
        })
}
```

Adjust the exact implementation as needed, but preserve these properties:

- no more than `max_stalled` live permits can be acquired concurrently;
- rejection metric increments only when acquisition fails because the cap is reached;
- no `record_stall_start()` call is needed for permit acquisition unless it is changed into a safe internal helper;
- behavior with `max_stalled == 0` should be explicit and tested; recommended behavior is always reject.

If `fetch_update` is not desired, use a `compare_exchange` loop.

## Phase 2 — Split Release and Timeout Metrics

`record_stall_end()` currently decrements active stalled requests and increments `STALL_TIMEOUTS`. With RAII, this mixes two events:

- permit release;
- stall sleep completed and timed out as designed.

Refactor to clarify semantics.

Suggested API:

```rust
pub fn release_stall_permit() {
    ACTIVE_STALLED_REQUESTS.fetch_sub(1, Ordering::Release);
}

pub fn record_stall_timeout() {
    STALL_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
}
```

Then:

- `Drop for StallPermit` calls only `release_stall_permit()`.
- Code paths that complete the full configured sleep call `record_stall_timeout()` explicitly before or after dropping the permit.
- Cancellation/drop releases the counter but does not increment `STALL_TIMEOUTS`.

Compatibility options:

- Keep `record_stall_end()` as a deprecated/compatibility wrapper only if other code still calls it.
- If retained, document it clearly or rename its semantics.
- Prefer removing direct production calls to `record_stall_start()` / `record_stall_end()` outside tests if feasible.

## Phase 3 — Fix Streaming WAF Stall Cap Behavior

Update `crates/synvoid-http/src/streaming_waf_decision.rs`.

Current problematic shape:

```rust
let permit = StallPermit::try_new(http_config.max_stalled_requests);
tokio::time::sleep(stall_timeout).await;
drop(permit);
```

Required behavior:

```rust
let permit = match StallPermit::try_new(http_config.max_stalled_requests) {
    Some(permit) => permit,
    None => {
        return Some(build_response_with_alt_svc(
            429,
            "Too many requests".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        ));
    }
};

tokio::time::sleep(stall_timeout).await;
record_stall_timeout();
drop(permit);
return Some(timeout_response);
```

Match the full HTTP/1/2 stall response as closely as practical.

Ensure this path does not sleep when the cap is reached.

## Phase 4 — Align Full Request and HTTP/3 Timeout Metrics

Review these files:

- `crates/synvoid-http/src/waf_decision.rs`
- `crates/synvoid-http/src/http3_waf_dispatch.rs`
- `crates/synvoid-http/src/streaming_waf_decision.rs`
- `crates/synvoid-http/src/buffered_request_waf_dispatch.rs`
- `src/tls/server.rs`

For each `WafDecision::Stall` path:

- permit acquisition should be strict and checked;
- cap rejection should return a bounded response or protocol-appropriate early return;
- completed sleep should record timeout metric explicitly;
- permit release should be automatic on `Drop`;
- no manual start/end closures should remain;
- direct manual calls to `record_stall_start` / `record_stall_end` should be test-only or removed.

If a path has protocol-specific behavior that cannot return HTTP `429`, document why in code comments.

## Phase 5 — Tests

Add focused tests in the most local crates.

### Metrics tests

Add tests for `StallPermit` in `synvoid-metrics` or the existing metrics test module:

1. `stall_permit_rejects_when_limit_zero`
2. `stall_permit_acquires_below_limit`
3. `stall_permit_rejects_at_limit`
4. `stall_permit_drop_releases_active_count`
5. `stall_permit_strict_atomic_cap_under_concurrency`

The concurrency test should spawn multiple tasks or threads attempting to acquire permits with a small cap and assert that successful acquisitions never exceed the cap. If shared global state makes exact assertions noisy, use a test-only reset helper gated under `#[cfg(test)]`.

### Streaming WAF tests

Add tests for `maybe_handle_streaming_waf_decision`:

1. below cap: `Stall` sleeps and returns `408` timeout response;
2. at cap: `Stall` returns `429` immediately and does not sleep;
3. permit releases after completed sleep;
4. cancellation/drop of the future releases the active count if testable.

Use very small durations or paused Tokio time if available.

### Existing path regression tests

Keep or update existing HTTP/3 tests:

- `http3_stall_allows_when_below_limit`
- `http3_stall_returns_429_when_limit_reached`
- `http3_stall_releases_permit_after_completion`
- `http3_stall_uses_configured_stall_limit`

Update them to avoid relying on global counter residue. Prefer owning permits in local vectors and dropping them deterministically.

## Phase 6 — Documentation

Update docs only if semantics change materially.

Suggested updates:

- `architecture/http3_request_waf_boundary.md`
  - note that stall concurrency is guarded by strict RAII permits;
  - note that streaming WAF stall path also enforces the cap.

- `docs/HTTP3.md`
  - if stall timeout/cap metrics are documented, distinguish:
    - active stalled requests;
    - stall cap rejections;
    - completed stall timeouts.

- `AGENTS.md` or relevant override files
  - add a concise warning: do not manually call stall start/end in production paths; use `StallPermit`.

## Verification Commands

Run focused checks:

```bash
cargo test -p synvoid-metrics stall
cargo test -p synvoid-http stall
cargo test -p synvoid-http streaming_waf_decision
cargo test -p synvoid-http3
cargo test --test http3_waf_boundary_guard
cargo test --lib --no-run
```

Adjust exact test filters to match final test names.

If GitHub statuses are absent, list local commands run in the implementation note.

## Acceptance Criteria

This cleanup is complete when:

1. `StallPermit::try_new` uses an atomic acquire and cannot oversubscribe the cap under concurrent callers.
2. `max_stalled_requests == 0` behavior is explicit and tested.
3. Streaming WAF `Stall` returns a cap response when no permit is available and does not sleep.
4. Completed stall sleeps increment timeout metrics explicitly.
5. Cancelled/dropped stall futures release the active counter without recording a completed timeout.
6. Direct production calls to manual stall start/end helpers are removed or clearly compatibility-only.
7. Tests cover strict acquisition, release, cap rejection, and streaming WAF cap behavior.
8. HTTP/3 remains free of concrete root-owned WAF/app service imports.
9. No broad WAF/HTTP architecture churn is introduced.

## Notes for the Implementer

This is the final stall-accounting hardening pass. Keep the changes mechanical and local. The desired model is:

> `StallPermit` owns active-stall accounting. Acquiring it is strict and atomic. Dropping it always releases the active slot. Completed sleeps record timeout metrics explicitly. Every WAF `Stall` path must either acquire a permit before sleeping or return a bounded cap response.
