# HTTP/3 Stall Concurrency Parity — Iteration 40

## Purpose

Iteration 39 audited the HTTP/3 request/WAF composition boundary and documented one concrete behavioral parity gap: HTTP/1/2 caps concurrent WAF `Stall` responses via the configured stall limit, while HTTP/3 currently sleeps without the same concurrency cap.

This pass should close that gap narrowly. The goal is not to redesign WAF decision handling or HTTP/3 dispatch. The goal is to make HTTP/3 `WafDecision::Stall` behavior match HTTP/1/2 semantics closely enough that stall-based tarpitting cannot create unbounded concurrent sleep tasks or resource retention on the HTTP/3 path.

## Current Known State

From `architecture/http3_request_waf_boundary.md`:

- HTTP/1/2 `Stall` response is concurrency-capped and returns `429` when the cap is reached.
- HTTP/3 `Stall` response currently performs an uncapped sleep and has no `429` cap behavior.
- This is the main remaining HTTP/3/WAF parity follow-up from Iteration 39.

Expected final state:

- HTTP/3 `Stall` uses the same or equivalent configured concurrency cap as HTTP/1/2.
- If the cap is reached, HTTP/3 returns a bounded response instead of starting another stall sleep.
- Metrics/logging remain clear enough to tell capped stalls from executed stalls.
- The implementation preserves HTTP/3 protocol-adapter ownership: no concrete root WAF/app service imports into `crates/synvoid-http3`.

## Non-Goals

Do not redesign `WafDecision`.

Do not change threat-intel policy behavior.

Do not change challenge, block, tarpit, or drop decision semantics except where test scaffolding requires minor factoring.

Do not add browser-specific HTTP/3 challenge routes.

Do not move concrete `WafCore`, `BlockStore`, `ChallengeManager`, or root-owned services into `crates/synvoid-http3`.

Do not introduce request-path DHT/network lookups.

Do not create a full cross-protocol WAF response abstraction unless a tiny shared helper already exists and makes the change smaller.

## Phase 1 — Locate HTTP/1/2 Stall Semantics

Inspect the HTTP/1/2 WAF decision path and identify the canonical stall implementation.

Search terms:

- `WafDecision::Stall`
- `max_stalled_requests`
- `stalled_requests`
- `Stall`
- `429`
- `Too Many Requests`
- `maybe_handle_waf_decision`
- `maybe_handle_http3_waf_decision`
- `http3_waf_dispatch`
- `http_waf_dispatch`

Document the HTTP/1/2 behavior in code comments or tests:

- what counter/semaphore is used;
- where it lives;
- how the cap is configured;
- what response is returned when the cap is exceeded;
- whether the counter is decremented on normal completion, early error, and task cancellation.

Do not proceed until the actual HTTP/1/2 behavior is verified in code.

## Phase 2 — Locate HTTP/3 Stall Path

Inspect the HTTP/3 WAF decision mapping.

Expected files/symbols from Iteration 39:

- `crates/synvoid-http/src/http3_waf_dispatch.rs`
- `maybe_handle_http3_waf_decision()`
- `WafDecision::Stall`
- `Http3RequestWaf`
- `Http3WafBackend`
- `Http3Server::handle_request()`

Confirm whether HTTP/3 stall is handled in `synvoid-http` or `synvoid-http3`.

Preferred ownership:

- HTTP/3 protocol crate should remain a protocol adapter.
- If the stall decision mapping lives in `synvoid-http`, put the cap there or in a shared narrow helper.
- If HTTP/3 must receive a stall limiter, inject it through a narrow trait/config/parameter, not by importing root-owned WAF implementation details.

## Phase 3 — Choose the Minimal Cap Mechanism

Preferred options, in order:

### Option A — Reuse existing WAF/HTTP stall limiter

If HTTP/1/2 already has a reusable stall limiter object, semaphore, or helper, route HTTP/3 through it.

Requirements:

- no concrete root service imports into `crates/synvoid-http3`;
- no duplicated counter logic if a shared helper can be used cleanly;
- no lock held across sleep unless existing design intentionally does so safely.

### Option B — Extract small shared helper into `synvoid-http` or `synvoid-waf`

If HTTP/1/2 cap logic is embedded in one handler, extract a small helper such as:

```rust
pub struct StallPermit { /* RAII decrement/drop */ }

pub trait StallLimiter {
    fn try_acquire_stall(&self) -> Option<StallPermit>;
}
```

or a simpler function if existing state is passed directly.

The helper should be small and not own policy. It only controls concurrency around executing a stall sleep.

### Option C — Add HTTP/3-local limiter using existing config

If sharing is too invasive, add a small HTTP/3-local limiter using the same config value and equivalent behavior.

This is acceptable only if:

- it is documented as equivalent but not physically shared;
- tests prove the cap behavior;
- ownership remains clean.

## Phase 4 — Define HTTP/3 Cap Response

Match HTTP/1/2 as closely as protocol-appropriate.

Preferred behavior:

- if stall permit acquired: perform configured stall delay, then continue with the existing HTTP/3 stall response behavior;
- if permit not acquired: return HTTP `429 Too Many Requests` with a small bounded body, likely JSON or plain text consistent with other HTTP/3 error responses.

Questions to resolve from code:

- Does HTTP/3 currently return any response for `Stall`, or does it only sleep and then close/continue?
- Does HTTP/3 decision mapping already have response builders for status/body/headers?
- Are metrics emitted for capped stalls in HTTP/1/2? If yes, mirror them or add a clearly named metric stub.

Do not add large response-format unification. Keep the HTTP/3 response format consistent with existing HTTP/3 `Block`/error response style.

## Phase 5 — Ensure Cancellation-Safe Accounting

The cap must not leak permits/counters.

If a semaphore is used, prefer RAII-owned permits.

If an atomic counter is used, ensure decrement happens on all exits:

- normal sleep completion;
- write error;
- request cancellation/drop;
- early return after cap response.

Avoid spawning detached sleeps that retain permits after request cancellation unless intentionally bounded and documented.

## Phase 6 — Tests

Add focused tests for the HTTP/3 stall path.

Required tests:

1. HTTP/3 `Stall` acquires a permit and executes the stall path when below cap.
2. HTTP/3 `Stall` returns cap response when the configured limit is reached.
3. Permit/counter is released after stall completion.
4. Permit/counter is released if response write fails or the future is dropped, if testable.
5. HTTP/1/2 and HTTP/3 use the same configured cap value or equivalent configuration source.
6. Boundary guard still passes: no concrete root WAF/app service imports into `crates/synvoid-http3`.

If the actual decision-mapping function is hard to test directly, extract a tiny pure/helper function for cap response selection and test that. Keep extraction narrow.

Suggested test names:

- `http3_stall_allows_when_below_limit`
- `http3_stall_returns_429_when_limit_reached`
- `http3_stall_releases_permit_after_completion`
- `http3_stall_uses_configured_stall_limit`

## Phase 7 — Documentation Updates

Update `architecture/http3_request_waf_boundary.md`:

- Change `Stall` parity from “HTTP/3 uncapped sleep” to “HTTP/3 capped equivalent to HTTP/1/2”.
- Remove or resolve the future-work bullet for stall concurrency cap.
- Add a short note describing where the limiter lives.

If `AGENTS.md` has HTTP/3/WAF testing commands, ensure it includes the relevant stall/concurrency test command if applicable.

## Phase 8 — Verification Commands

Run focused tests:

```bash
cargo test --test http3_waf_boundary_guard
cargo test -p synvoid-http3
cargo test -p synvoid-http http3
cargo test -p synvoid-http stall
cargo test -p synvoid-waf
cargo test --lib --no-run
```

Adjust package/test names to match the actual test placement.

If GitHub CI status remains unavailable, document the local commands run in the implementation note.

## Acceptance Criteria

This pass is complete when:

1. HTTP/3 `WafDecision::Stall` cannot create unbounded concurrent stall sleeps.
2. HTTP/3 uses the same stall cap configuration or an explicitly equivalent source as HTTP/1/2.
3. Cap-exceeded behavior returns a bounded HTTP/3 response, preferably `429`.
4. Permit/counter accounting is cancellation-safe and does not leak.
5. Tests cover under-cap, over-cap, release behavior, and configuration linkage.
6. `crates/synvoid-http3` remains free of concrete root-owned WAF/app service imports.
7. `architecture/http3_request_waf_boundary.md` reflects the resolved parity status.
8. No broad WAF or HTTP/3 redesign is introduced.

## Notes for the Implementer

This should be a small parity fix. The architecture is already in good shape after Iteration 39. Do not turn this into a larger response-mapping refactor unless the current code makes a tiny shared helper clearly cheaper than duplication.

The important invariant is:

> A malicious client should not be able to trigger unbounded concurrent HTTP/3 stall sleeps. HTTP/3 must apply a bounded stall permit just like HTTP/1/2, while remaining only a protocol adapter over narrow WAF traits.
