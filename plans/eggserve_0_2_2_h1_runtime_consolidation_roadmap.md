# EggServe 0.2.2-Line H1 Runtime Consolidation Roadmap

Status: campaign closed at Phase 65 as **RETAINED** on 2026-09-24. Production remains on Hyper H1; Phases 66–69 were not started because EggServe's required finite handler/body/write deadlines and upper bounds do not preserve current SynVoid semantics. Evidence: `architecture/eggserve_0_2_2_h1_compatibility_matrix.md`.

Registered in: `plans/roadmap.md`.

Baseline reviewed: `main` at `11a1fb2844cd648418eefd72801f1aee2090d140` (2026-09-24 review against the current repository state).

Upstream line reviewed:

- `eggserve-core 0.2.2` is published and registry-qualified;
- the direct reusable H1 runtime remains `eggserve-server 0.2.1`;
- the canonical primitives resolved by the published line remain `eggserve-primitives 0.2.0`;
- `eggserve-core 0.2.2` specifically repairs/qualifies the optional HTTP/Tower adapter and Axum 0.8 composition; it does not imply that an `eggserve-server 0.2.2` artifact exists.

This campaign intentionally names the upstream line truthfully. The production target is the narrow direct H1 runtime unless Phase 65 proves that the heavier core adapter is materially required.

## Primary goal

Move generic inbound HTTP/1 connection/runtime mechanics out of SynVoid and behind EggServe where exact behavioral parity can be proven, while preserving SynVoid ownership of:

- socket binding and `SO_REUSEPORT`;
- pre-HTTP flood/admission checks;
- strict protocol sniffing;
- TLS termination, certificate/SNI policy, ALPN, PQ configuration, and JA4;
- HTTP/2 and HTTP/3 transports;
- trusted-proxy/client-IP policy;
- routing, WAF, challenges, uploads, plugins, backend dispatch, metrics, and application policy;
- public configuration and externally observable protocol behavior.

The intended end state is:

```text
TCP accept / TLS handshake / ALPN       SynVoid
                |
                +-- H1 byte stream ----> EggServe H1 runtime
                |                         |
                |                         +--> SynVoid transport-neutral request pipeline
                |                         +--> SynVoid WAF/routing/backends
                |
                +-- H2 -----------------> existing SynVoid Hyper H2 path
                +-- H3 -----------------> existing SynVoid H3 path
```

EggServe is a connection/runtime mechanism dependency, not a replacement for the SynVoid HTTP policy plane.

## Why this campaign is justified

The current plaintext path in `src/http/server/accept_loop.rs` owns generic Hyper H1 mechanics directly: listener-to-task dispatch, H1 parser configuration, upgrade-enabled connection driving, connection error handling, and connection lifecycle. The TLS path duplicates part of that work for ALPN-selected H1.

EggServe now exposes a caller-owned H1 driver:

`eggserve_server::connection::serve_http1_connection`

which accepts an arbitrary Tokio `AsyncRead + AsyncWrite` byte stream plus explicit connection context, shared runtime state, and shutdown capability. It can therefore sit below SynVoid policy without taking ownership of the listener, TLS handshake, or H2/H3.

The blocker is downstream architecture rather than missing upstream transport capability: `synvoid-http` still uses `hyper::body::Incoming` and `hyper::upgrade::OnUpgrade` as canonical pipeline types. That must be neutralized before a clean EggServe runtime substitution.

## Hard ownership boundary

This campaign MUST NOT:

- hand the primary listener to EggServe in the first adoption;
- move TLS certificate resolution or ALPN selection into EggServe;
- replace SynVoid's H2/H3 stacks;
- import EggServe static-serving policy into SynVoid;
- move WAF/routing/backend policy into EggServe;
- enable the core `tls`, `http2`, or `http3` orchestration merely because the compatibility crate exposes them;
- retain two production H1 runtimes permanently.

Prefer direct leaf crates in production:

```toml
eggserve-server = { version = "=0.2.1", default-features = false }
eggserve-primitives = { version = "=0.2.0", default-features = false }
```

Phase 65 may use `eggserve-core = "=0.2.2"` with `http-interop` or `tower` for qualification/prototyping, but it must not become a production dependency unless evidence shows that the direct leaf boundary cannot satisfy the integration without recreating upstream interop code.

## Configuration rule

Do not apply `RuntimeConfig::default()` directly.

Every EggServe control must be classified against an existing SynVoid policy before production use. In particular:

- `header_read_timeout` should project from `http.header_read_timeout_secs`;
- `keep_alive_idle_timeout` should project from `http.keep_alive_timeout_secs`;
- `max_headers` should project from `http.max_headers`;
- request-target/header/body ceilings must be mapped from the current SynVoid meanings, not field-name similarity;
- `connection_total_timeout` must start disabled (`Duration::ZERO`) because SynVoid does not currently impose EggServe's default 60-second hard connection lifetime;
- `max_request_body_bytes` must be explicitly raised from EggServe's reject-body default to the proven SynVoid body ceiling;
- mandatory EggServe handler/body/write/admission controls with no exact SynVoid equivalent must either be configured to a proven non-interfering value, adopted through an explicit behavior decision with tests/docs, or treated as a blocker.

Do not invent a new operator policy silently.

## Execution order

The initial qualification was executed on baseline `79379d555ca4a8b6359760af2052a6e8228c3cfd`. It selected `RETAIN_CURRENT_H1`; the remaining phases below are gated and are not active work until the upstream contract changes and Phase 65 is repeated.

### Phase 65 — Runtime qualification and boundary contract

Plan: `plans/phase_65_eggserve_runtime_qualification_and_boundary_contract.md`.

Pin/qualify the published line without changing production routing. Produce the dependency/config/semantic matrix, inventory Hyper-specific request/upgrade coupling, prove direct-leaf response/body/tunnel adaptation feasibility, and make an explicit go/retain decision.

### Phase 66 — Transport-neutral request/body/tunnel boundary

Plan: `plans/phase_66_http_transport_neutral_request_and_tunnel_boundary.md`.

Refactor `synvoid-http` so its canonical request path no longer requires `hyper::body::Incoming` or `hyper::upgrade::OnUpgrade`. Keep the existing Hyper H1/H2 runtime active and prove behavior is unchanged. This phase is valuable even if EggServe adoption later stops.

### Phase 67 — Plaintext H1 EggServe adoption

Plan: `plans/phase_67_eggserve_plaintext_h1_runtime_adoption.md`.

Add the direct EggServe H1 service adapter and replace only the plaintext H1 connection driver. Preserve SynVoid listener/flood/protocol-sniff behavior and keep a bounded differential test lane until final qualification.

### Phase 68 — TLS/ALPN H1 convergence

Plan: `plans/phase_68_eggserve_tls_h1_runtime_convergence.md`.

Keep SynVoid TLS termination and ALPN. Route only successfully negotiated HTTP/1.1 TLS streams through the same EggServe H1 runtime used by plaintext. Leave H2 unchanged.

### Phase 69 — Adversarial/performance qualification and closeout

Plan: `plans/phase_69_eggserve_h1_adversarial_performance_and_closeout.md`.

Run final parser/framing/body/upgrade/shutdown/security and immutable performance qualification, delete the superseded production Hyper H1 driver only after parity, reconcile docs/evidence, and close with either adopted or retained ownership.

## Global invariants

All phases must preserve:

- WAF decision ordering and fail-closed framing behavior;
- trusted-proxy/client-IP resolution;
- host/local-address routing semantics;
- internal health/ready/drain behavior;
- request-body WAF scanning and streaming bounds;
- WebSocket handshake validation and bidirectional tunnel behavior;
- backend selection and proxy semantics;
- response transformations, Alt-Svc behavior, metrics, logging, and bandwidth accounting;
- TLS/PQ/SNI/certificate/JA4 behavior;
- H2/H3 support and feature profiles;
- public configuration keys/defaults unless a separate compatibility decision explicitly changes them;
- no unbounded queue/task/stream introduced at the adapter boundary.

## Differential-evidence rule

Until Phase 69 closes, maintain a way to compare the existing H1 driver and the EggServe H1 driver under the same hermetic fixtures. This may be test-only or qualification-only; it must not become a permanent operator-facing dual-runtime switch.

Compare observable behavior, including:

- status and headers;
- duplicate/opaque headers where supported;
- body bytes and trailers;
- connection reuse/close;
- malformed framing rejection;
- timeout/limit behavior;
- upgrade/tunnel success/failure;
- disconnect cleanup;
- shutdown/drain;
- metrics/log classifications that are contractual.

## Performance rule

This is primarily a maintenance/security ownership consolidation, not a benchmark contest, but the ingress hot path must not regress materially without an explicit adjudication.

Use immutable before/after revisions and the same harness. Treat an unexplained >5% regression in a primary throughput or p95/p99 latency measure as material until localized. Measure at least:

- short H1 keep-alive requests;
- concurrent H1 requests;
- 64 KiB and larger request/response streaming;
- WebSocket/tunnel establishment;
- idle keep-alive;
- connection churn;
- allocator/RSS impact when practical.

Do not remove the old production driver solely for LOC reduction if the replacement has an unresolved material regression.

## Campaign terminal states

**Adopted:** direct EggServe H1 runtime drives plaintext and TLS-H1, SynVoid retains transport/policy authority above it, the superseded production Hyper H1 driver is removed, H2/H3 remain unchanged, and final correctness/security/performance evidence is recorded.

**Retained:** a concrete blocker is recorded with an executable failing parity/security/API/performance test, production remains on the existing Hyper H1 runtime, qualification-only EggServe wiring is removed, and the transport-neutral Phase 66 boundary may remain if independently beneficial.

No permanent "half migrated" state with both generic H1 runtimes active in production.
