# Admin Panel Phase 4 — Realtime Metrics, WebSocket Behavior, and Operator-State Correctness

## Status

**PLANNED**

## Objective

Make realtime/admin status presentation reflect actual SynVoid runtime state, operate correctly under both HTTP and HTTPS deployment, and degrade predictably from WebSocket streaming to bounded polling without duplicate timers, stale false-connected state, or inert operator controls.

This phase assumes Phases 1–3 have established correct routing, session authentication, and endpoint contracts.

## Scope

Primary files expected to change:

- `admin-ui/src/hooks/use_websocket.rs`
- `admin-ui/src/components/realtime_header.rs`
- `admin-ui/src/pages/dashboard.rs`
- any other component using the realtime hooks
- `src/admin/ws.rs`
- `src/admin/metrics.rs`
- `src/admin/state.rs` and shared metrics payload types only where actual runtime state must be carried to the UI
- `crates/synvoid-metrics/*` only if the canonical metrics payload belongs there
- focused WebSocket/polling/metrics tests

Do not redesign the metrics subsystem or add a new telemetry backend.

## Baseline problems

- WebSocket URL construction always emits `ws://`, which breaks an HTTPS-loaded dashboard through mixed-content restrictions.
- token-accepting WebSocket hook variants ignore their token parameters, reflecting unclear auth semantics.
- fallback polling can create timers on close/error paths without a single explicit state machine, risking duplicate intervals or stale status.
- the realtime header labels a derived request-rate heuristic as "Threat Level" instead of reporting the threat-level subsystem.
- displayed range buttons (`1m`, `5m`, `15m`, `1h`) are inert.
- connection state presentation can remain misleading when WebSocket data is stale but no new sample is arriving.

## Implementation plan

### 1. Replace ad hoc WebSocket URL parsing with browser-location-derived scheme/host

Construct WebSocket URL from `window.location` components:

- `https:` page -> `wss:` WebSocket
- `http:` page -> `ws:` WebSocket
- preserve host including non-default port
- append the canonical API WebSocket path

Do not parse the full `href` manually if browser APIs expose protocol/host directly.

Support same-origin deployment first. If a separately configured admin API origin is already supported, derive its WebSocket scheme equivalently rather than hard-coding.

### 2. Remove obsolete token parameters from browser hooks

After Phase 2, browser WebSockets authenticate from the HttpOnly session cookie. Therefore:

- remove `use_websocket_with_token`/`use_websocket_or_poll_with_token` token parameters or rename/refactor them so their signature matches actual behavior
- remove `get_auth_token()` from realtime components
- ensure no long-lived bearer token is needed for realtime paths

Do not keep misleading unused security parameters.

### 3. Implement one explicit connection/fallback state machine

The hook should have one clear lifecycle:

- `Connecting`
- `Connected(data, last_received)` conceptually
- `Polling`/degraded state if WebSocket unavailable
- `Disconnected`/unauthenticated terminal state as appropriate
- `Error` with bounded detail

Required behavior:

- at most one active WebSocket per hook instance
- at most one polling interval per hook instance
- closing/erroring WebSocket transitions to polling once
- cleanup closes socket and cancels polling interval
- successful WebSocket reconnection, if implemented, cancels polling before streaming resumes
- session-expiry responses stop reconnect/poll attempts and hand control to Phase 2 auth recovery

A full generic networking framework is not required. Keep this specific to the admin realtime use case.

### 4. Bound reconnection behavior

If automatic WebSocket reconnection is retained/added:

- use bounded exponential or stepped backoff with a maximum interval
- do not retry faster than once per second
- do not create unbounded tasks/timers
- stop retries when component unmounts or session becomes invalid
- reset backoff after a stable successful connection

If simple polling-only fallback is more reliable for this project size, it is acceptable to remain on polling until page refresh rather than adding complex reconnect orchestration.

### 5. Add data freshness semantics

Track the timestamp of the last accepted realtime sample.

UI behavior:

- "Live" only when the stream/poll is active and data age is within a reasonable multiple of expected update cadence
- "Stale" when the connection object exists but samples are not arriving
- "Polling" when degraded fallback is active
- "Disconnected" when neither channel is active

Do not animate a green live indicator indefinitely from one historical sample.

### 6. Carry the actual threat level in the canonical realtime payload

The current UI must stop deriving threat level from request rate.

Use the real threat-level manager/status already exposed by the admin backend. Add the smallest payload field needed, for example:

- actual current level
- optional auto/manual/learning state if useful and already available

Source the value server-side from the canonical threat-level subsystem at publish/sample time. Do not duplicate threat scoring logic in the frontend.

If the threat-level subsystem is unavailable, return `None`/an explicit unavailable state rather than inventing zero/low.

### 7. Make threat labels match the actual model

The server threat-level mutation/status contract uses levels 1–5. The realtime UI must use the same domain and labels/colors.

Do not retain the current 0–10 request-rate-derived classification.

If a canonical level-to-label mapping already exists in the UI/backend, reuse it.

### 8. Wire history/range controls or remove them

The `1m`, `5m`, `15m`, `1h` controls must affect behavior as labeled.

Preferred implementation:

- store selected history window
- map it to the existing `/stats/history?seconds=<N>` request
- refresh sparkline/history state for that window
- visually mark selected window

If the current backend history endpoint cannot provide the required windows without significant new subsystem work, retain only the windows it genuinely supports and remove unsupported buttons.

Do not ship inert buttons.

### 9. Separate instantaneous streaming from historical chart data cleanly

Realtime stream should provide current counters/rates. Historical endpoint should provide enough samples for the selected sparkline/chart window.

Avoid growing history indefinitely in component state from every realtime sample. Bound in-memory history to the visible sample budget.

### 10. Correct success-rate arithmetic edge cases

Review current success-rate calculation for underflow/invalid values when `blocked + errors > total_requests` due to asynchronous counters or semantics.

Use saturating/validated arithmetic server-side or frontend-side as appropriate and clamp displayed percentages to a sensible range.

Do not panic or wrap unsigned subtraction in WASM.

### 11. Ensure realtime payload compatibility is explicit

If adding fields to `RealtimeMetrics`:

- use `#[serde(default)]`/optional fields where backward-compatible decoding is desirable
- update server and frontend canonical type definitions together
- avoid maintaining divergent duplicate structs if one shared payload crate/type can be used without creating an awkward WASM dependency

Prefer a small compatibility addition over broad metrics type migration.

### 12. Surface mutation/application state truthfully in nearby operator UI

For controls whose effect is asynchronous or requires reload/restart, display returned mutation/application status rather than immediately implying completion.

This applies especially to:

- worker restart/scale state refreshed after Phase 3 operations
- threat level manual/auto changes
- configuration changes marked pending/reload-required

Do not invent a new global state manager; use existing per-page state and typed mutation results.

## Focused tests

### URL/scheme tests

Factor URL construction into a testable helper where practical and prove:

- HTTP origin -> `ws://host/...`
- HTTPS origin -> `wss://host/...`
- custom port is preserved
- path is canonical

### WebSocket/fallback lifecycle tests

At the Rust/unit level where feasible, or through small hook/state helper tests, prove:

- one close event produces one polling interval
- error followed by close does not produce two polling intervals
- cleanup cancels active interval/socket
- successful stream sample marks data fresh
- stale timeout changes displayed state

### Realtime payload tests

Prove actual threat level from a test threat manager/status reaches the serialized realtime payload and deserializes in the frontend type.

### Range tests

Prove each retained time-range control maps to the expected history request duration and selected state.

## Acceptance criteria

Phase 4 is complete only when:

- HTTPS-origin dashboards construct `wss://` WebSocket URLs and HTTP-origin dashboards construct `ws://` URLs
- realtime browser code no longer reads or accepts the long-lived admin bearer token
- one hook instance cannot maintain duplicate polling intervals after WebSocket close/error sequences
- cleanup reliably closes/cancels realtime resources
- unauthenticated/session-expired realtime paths stop background retry activity and transition to the auth recovery path
- connection status distinguishes live, stale, polling/degraded, and disconnected states truthfully
- the realtime metrics payload includes the actual current threat level or an explicit unavailable state from the backend
- the UI no longer derives threat level from requests-per-second
- threat level labels use the same 1–5 domain as the actual threat-level subsystem
- success-rate arithmetic cannot underflow or display nonsensical percentages from counter skew
- each visible `1m`/`5m`/`15m`/`1h` control actually changes the requested/displayed history window; unsupported inert controls are removed
- historical samples retained client-side are bounded
- focused WebSocket/fallback/realtime tests pass
- no new telemetry service, generic reconnect framework, or admin-specific CI lane is introduced

## Rejection criteria

Reject this phase if it:

- fixes HTTPS by disabling mixed-content/browser security
- sends bearer tokens in WebSocket URLs
- leaves unused `_token` parameters in security-sensitive hook APIs
- starts polling on both `onerror` and `onclose` without deduplication
- labels a traffic-volume heuristic as threat level
- keeps inert time-range buttons
- accumulates unbounded sample history in WASM memory
- adds a new metrics database solely for the admin dashboard

## Verification commands/evidence

Record focused tests plus one local HTTP and one HTTPS-equivalent browser check (for example through the documented local TLS reverse-proxy mode):

```bash
cargo test --profile ci <admin-realtime-test-target>
cargo test --profile ci <admin-metrics-payload-test-target>
```

For the browser check, verify DevTools/network shows `ws://` on local HTTP and `wss://` on HTTPS, then force WebSocket failure and confirm exactly one bounded polling fallback remains active.
