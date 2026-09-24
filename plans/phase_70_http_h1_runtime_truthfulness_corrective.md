# Phase 70 Plan: HTTP/1 Runtime Truthfulness Corrective

Status: implementation handoff plan.

Registered in: `plans/roadmap.md`.

Baseline reviewed: `main` at `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c` (2026-09-24).

Context: the EggServe 0.2.2-line campaign closed `RETAIN_CURRENT_H1` at Phase 65. This corrective is independent of EggServe adoption. It fixes concrete truthfulness/asymmetry defects exposed by that qualification while production remains on Hyper.

## Primary goal

Make the currently supported HTTP/1 transport behavior match the repository's logs, configuration claims, and plaintext/TLS-H1 parser policy without reopening the retained EggServe migration.

This phase owns three proven residuals:

1. the plaintext startup log advertises `HTTP/1.1 + HTTP/2` even though the plaintext accept loop constructs only `hyper::server::conn::http1::Builder`;
2. plaintext H1 applies `header_read_timeout_secs`, `max_headers`, and `max_request_size` to the Hyper parser, while TLS-H1 computes the corresponding values but does not apply the header timeout or parser-buffer ceiling and only applies a header-list limit to H2;
3. the top-level roadmap status still says the retained EggServe Phases 65–69 campaign is "implementation-ready" even though Phase 65 closed `RETAIN_CURRENT_H1` and Phases 66–69 are gated/not started.

The planning-registration commit may correct item 3 immediately as bookkeeping. Runtime items 1–2 require implementation and tests.

## Non-goals

- No EggServe production dependency.
- No Phase 66–69 transport-neutral refactor.
- No h2c/prior-knowledge HTTP/2 implementation merely to preserve a stale log string.
- No TLS termination, ALPN, PQ, JA4, certificate, routing, WAF, or backend redesign.
- No broad `HttpConfig` dormant-field campaign; Phase 71 owns that audit.
- No change to HTTP/2 limits except where a test proves an accidental regression from sharing configuration.
- No new operator-visible timeout or limit beyond configuration that is already documented as active.

## Workstream A — Correct protocol capability reporting

In `src/http/server/accept_loop.rs`, make the startup message truthful for the actual plaintext transport.

Preferred result while the driver remains H1-only:

```text
HTTP server listening on ... (HTTP/1.1) [SO_REUSEPORT]
```

Do not write "H1-only" into a user-facing message if the repository's logging convention prefers protocol names; simply advertise what is actually served.

Audit current HTTP architecture/user docs for claims that plaintext supports H2/h2c. Correct only claims proven false by the current driver. Keep HTTPS `HTTP/1.1 + HTTP/2` claims because ALPN routing actually supports both.

Add a source-level or behavior-level guard that prevents the plaintext startup claim from drifting back to H2 unless a real plaintext H2 driver exists.

## Workstream B — Make TLS-H1 parser controls match plaintext H1

The current plaintext builder applies:

- `header_read_timeout(Duration::from_secs(http_config.header_read_timeout_secs))`;
- `max_headers(http_config.max_headers)`;
- `max_buf_size(http_config.max_request_size)`.

The TLS server currently computes:

- `_header_read_timeout`;
- `max_headers`;
- `_max_buf_size`;

but its H1 builder only calls `.keep_alive(true)` before `serve_connection(...).with_upgrades()`.

Apply the same transport-independent H1 parser controls to the TLS-H1 builder.

### Hyper timer requirement

Before coding, confirm the exact resolved Hyper API requirement for `header_read_timeout`. If the resolved builder requires an explicit timer, use the canonical Tokio timer adapter available in the current dependency graph (for example the appropriate `hyper-util` Tokio timer) and use the same safe construction on every H1 path that enables the timeout.

Do not leave plaintext relying on an implicit/default timer while TLS uses another timing mechanism. If the audit discovers plaintext's current timeout is not actually active because a timer is missing, fix both H1 paths together and add executable proof.

### Keep H2 separate

Do not mechanically map `max_request_size` to H2 flow-control/body limits. H2 framing and header-list semantics differ. Preserve the existing H2 `max_header_list_size(max_headers as u32)` behavior unless Phase 71 later classifies that configuration differently.

## Workstream C — Parser-control parity tests

Add focused loopback tests for plaintext H1 and TLS-H1 using the same configured values.

Required cases:

1. **max headers**
   - configure a small count;
   - request at/below the count succeeds far enough to reach normal dispatch;
   - request above the count is rejected at the transport/parser boundary;
   - plaintext and TLS-H1 have equivalent outcome class.

2. **parser buffer ceiling**
   - configure a valid small test value accepted by Hyper;
   - request headers/request target that fit succeed;
   - parser input exceeding the configured buffer is rejected;
   - prove the TLS-H1 path is no longer using Hyper's unrelated default.

3. **slow header timeout**
   - configure a short nonzero test timeout;
   - send a partial H1 header and hold the connection open;
   - prove both plaintext and TLS-H1 terminate/reject within a bounded tolerance;
   - avoid wall-clock-flaky assertions by using a generous upper bound relative to the configured timeout.

4. **WebSocket regression**
   - a normal upgrade still works over plaintext and TLS-H1 after builder changes;
   - `.with_upgrades()` remains present.

5. **H2 regression**
   - TLS ALPN h2 still selects the H2 path and its basic request fixture passes.

Do not assert private Hyper error strings.

## Workstream D — Remove misleading dead locals

After TLS-H1 actually consumes the values, remove underscore-prefixed "computed but unused" locals or factor one small helper that constructs the transport-independent H1 builder policy.

If a helper is introduced, keep it root-local and limited to Hyper H1 configuration. Do not create a new crate or generic server abstraction for three builder settings.

A reasonable shape is a function that accepts `&HttpConfig` and configures a supplied/new H1 builder, but exact type ergonomics are an implementation choice.

## Workstream E — Documentation/evidence truth

Create:

`architecture/http_h1_runtime_truthfulness_phase70.md`

Record:

- baseline SHA;
- exact plaintext and TLS-H1 builder behavior before;
- exact behavior after;
- timer requirement/result;
- protocol startup-message correction;
- focused test commands/results;
- H2/WebSocket regression evidence;
- any residual delegated to Phase 71.

Update as needed:

- `architecture/http_server.md`;
- `architecture/http_request_pipeline.md`;
- `.opencode/skills/httpserver/SKILL.md`;
- `plans/roadmap.md`.

Do not rewrite the Phase 65 EggServe compatibility record except to add a forward pointer if useful; it remains historical evidence for the retained decision.

## Verification

Focused:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo xtask test guards
```

Root/TLS integration suites that own the actual server types must also run; use the repository's current canonical package/integration targets rather than creating a second harness.

Profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Broader gate:

```bash
cargo xtask verify
```

Run `cargo deny check` / `cargo audit` if timer wiring changes dependency features or the lockfile.

## Acceptance criteria

Phase 70 is complete only when:

- top-level roadmap status no longer calls the retained EggServe migration implementation-ready;
- plaintext startup logs only the protocols its accept loop actually serves;
- plaintext H1 and TLS-H1 apply the same configured header-read timeout, max-header count, and parser-buffer ceiling;
- header timeout is proven active rather than merely configured;
- WebSocket upgrades still function on both H1 transports;
- TLS H2 remains unchanged and functional;
- no EggServe production code/dependency is introduced;
- architecture/skill docs describe the runtime truthfully;
- routine verification passes.

## Rejection criteria

Reject a closeout that:

- adds plaintext H2 solely to match the old log;
- changes H2 body/flow-control semantics while fixing H1;
- invents new timeout values instead of consuming existing config;
- claims TLS-H1 parity without executable slow-header/limit tests;
- reopens the EggServe campaign without a new upstream qualification.
