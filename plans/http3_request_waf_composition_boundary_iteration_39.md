# HTTP/3 Request/WAF Composition Boundary — Iteration 39

## Purpose

The threat-intel/WAF boundary work is complete enough to move to the adjacent request-path integration surface. The next architectural target is the HTTP/3 + request/WAF composition boundary.

The goal is to ensure HTTP/3 remains a protocol adapter, not an owner of WAF policy, BlockStore, challenge, GeoIP, violation persistence, or request-context construction semantics.

This pass should audit and tighten the seam between:

- `crates/synvoid-http3` protocol/server code;
- WAF traits and adapters;
- request context construction;
- streaming body scanning;
- unified worker service composition;
- HTTP/1/2 vs HTTP/3 WAF decision parity.

## Desired End State

HTTP/3 should depend only on narrow protocol-facing abstractions:

- an HTTP/3 request WAF trait, such as `Http3RequestWaf`, if already present;
- request/response primitives needed to translate protocol frames to WAF decisions;
- no concrete `BlockStore`, `ThreatIntelligenceManager`, challenge manager, GeoIP manager, or app-server internals.

WAF policy and services should be composed outside HTTP/3, preferably in the worker/data-plane composition root.

Request context construction should be consistent across HTTP/1/2 and HTTP/3, or the differences should be explicit and documented.

Streaming body WAF behavior should be consistent and documented across protocols, including early decisions, body chunk scanning, backpressure, and fail-open/fail-closed handling.

## Non-Goals

Do not redesign the WAF engine.

Do not add new WAF detection features.

Do not change threat-intel policy semantics.

Do not move ownership back into HTTP/3.

Do not perform a large protocol rewrite.

Do not change QUIC transport behavior unless necessary to fix WAF integration correctness.

Do not introduce request-path network lookups.

## Phase 1 — Inventory HTTP/3 and WAF Integration Surfaces

Search and inspect these symbols and paths:

- `Http3RequestWaf`
- `Arc<dyn Http3RequestWaf>`
- `RequestWaf`
- `WafProcessor`
- `WafCore`
- `ErasedBlockStore`
- `BlockListStore`
- `RequestContext`
- `BodyScanPhase`
- `check_request`
- `check_request_full`
- `check_body_chunk`
- `collect_body_with_chunk_waf`
- `stream_body_with_waf`
- `check_early`
- `check_block_store`
- `WafDecision`
- `Challenge`
- `crates/synvoid-http3/**`
- `crates/synvoid-waf/**`
- `src/waf/**`
- `src/http/**`
- `src/worker/unified_server/**`
- `src/waf/adapters.rs`

Create a short inventory table in a new or existing architecture document.

Suggested file:

- `architecture/http3_request_waf_boundary.md`

The table should classify each surface as:

1. protocol adapter;
2. WAF core;
3. WAF service adapter;
4. worker/data-plane composition;
5. request context builder;
6. body streaming adapter;
7. tests/fixtures.

## Phase 2 — Define Ownership Rules

Document ownership rules before changing code.

Required invariants:

1. `crates/synvoid-http3` owns HTTP/3 protocol handling only.
2. `crates/synvoid-http3` may call a narrow WAF trait, but must not import concrete WAF service state.
3. `src/waf` or `crates/synvoid-waf` owns WAF semantics and service traits.
4. `src/waf/adapters.rs` owns concrete adapters from application services to WAF traits.
5. `src/worker/unified_server/**` owns composition and injection of concrete services.
6. HTTP/3 must not construct or fetch `BlockStore`, `ThreatIntelligenceManager`, `GeoIpManager`, `ChallengeManager`, or violation persistence directly.
7. Request/WAF hot paths must not perform DHT/network lookups for policy decisions.
8. Body streaming WAF must preserve backpressure and not buffer unbounded bodies.

If any invariant is currently violated, fix it if the change is small; otherwise document it as a follow-up with exact file/function names.

## Phase 3 — Audit Crate Dependency Direction

Inspect `Cargo.toml` files and imports.

Focus on:

- `crates/synvoid-http3/Cargo.toml`
- `crates/synvoid-waf/Cargo.toml`
- root crate imports in HTTP/3 integration code
- any imports from `src/waf` into `crates/synvoid-http3`
- any imports from `src/worker` into protocol crates

Expected dependency shape:

- HTTP/3 crate may depend on protocol primitives, shared request types, and narrow WAF traits if intentionally exposed.
- HTTP/3 crate should not depend on root application modules or concrete runtime services.
- Root/worker code may depend on HTTP/3 and provide adapters into it.

If there is concrete coupling, prefer moving only the boundary trait or DTO into the lower/shared crate instead of pulling implementation details into HTTP/3.

## Phase 4 — Normalize Request Context Construction

Audit how `RequestContext` is built for HTTP/1/2 and HTTP/3.

Compare fields such as:

- client IP;
- method;
- URI/path/query;
- host/SNI/site identity;
- headers;
- protocol version;
- TLS/passthrough classification if relevant;
- body scan phase;
- tenant/site scope;
- request IDs/tracing metadata.

If HTTP/3 builds a partial or inconsistent context, extract or reuse a helper.

Preferred shape:

- a protocol-neutral request context builder/helper in a shared location;
- protocol adapters supply protocol-specific facts;
- WAF receives the same semantic context across HTTP/1/2/3.

Do not over-abstract. If a full helper is too much, add tests documenting parity for critical fields.

## Phase 5 — Audit WAF Decision Mapping

Compare how HTTP/1/2 and HTTP/3 map `WafDecision` to protocol responses/actions.

Check at least:

- allow/pass-through;
- deny/block;
- challenge response;
- redirect if supported;
- body scan continuation;
- early termination;
- error/fail-open/fail-closed behavior;
- logging and metrics;
- block-store updates caused by WAF escalation.

HTTP/3 may need different wire encoding, but semantic outcomes should match HTTP/1/2 where possible.

If there is no explicit mapping table, add one to `architecture/http3_request_waf_boundary.md`.

## Phase 6 — Audit Streaming Body WAF Behavior

Inspect body scanning flows for HTTP/1/2 and HTTP/3.

Key questions:

- Does HTTP/3 scan headers before body?
- Does it support chunk/stream scanning with `BodyScanPhase` or equivalent?
- Does it preserve backpressure?
- Does it stop reading when WAF returns a terminal decision?
- Does it avoid unbounded body buffering?
- Does it apply the same configured body limits as HTTP/1/2?
- Does it handle streaming errors consistently?

If HTTP/3 currently only performs header/early WAF checks, document that explicitly and add a follow-up item. Do not force a full streaming rewrite in this pass unless the code is already close.

## Phase 7 — Add Mechanical Guardrails Against Concrete Coupling

Add a lightweight source scan or architecture test similar to the threat-intel boundary guard.

Suggested test:

- `tests/http3_waf_boundary_guard.rs`

Guardrails:

1. Files under `crates/synvoid-http3/**` must not import concrete app/root services such as:
   - `crate::block_store`
   - `crate::waf::`
   - `crate::challenge`
   - `crate::geoip`
   - `crate::mesh`
   - `ThreatIntelligenceManager`
   - `BlockStore` concrete type, unless it is a trait/DTO specifically intended for the boundary.
2. HTTP/3 should use boundary traits/DTOs only.
3. Allow docs/tests/fixtures where necessary.

Do not make the guard too broad. It should catch obvious concrete coupling, not normal use of shared primitives.

If an architecture-test framework already exists, integrate there instead of creating a standalone pattern.

## Phase 8 — Tests

Add focused tests where code changes occur.

Recommended tests:

1. HTTP/3 WAF adapter can call the WAF trait without concrete WAF dependencies.
2. Request context builder produces equivalent critical fields for HTTP/1/2 and HTTP/3 fixtures.
3. WAF deny/challenge/allow decisions map to expected HTTP/3 responses/actions.
4. Streaming body WAF stops on terminal decision.
5. Boundary guard rejects a simulated concrete import from HTTP/3 into root WAF/app internals.

If the code is not structured for all of these tests, prioritize the boundary guard plus one context/decision mapping test.

## Phase 9 — Documentation

Add or update:

- `architecture/http3_request_waf_boundary.md`
- `AGENTS.md` path corrections or rules if needed
- relevant `AGENTS.override.md` files for HTTP/3/WAF if present

Docs should include:

- ownership matrix;
- dependency direction;
- request context construction rules;
- WAF decision mapping summary;
- streaming body WAF current status;
- explicit non-goals and future work.

Keep docs concise. The goal is to prevent integration drift, not create a large design essay.

## Verification Commands

Run focused checks based on modified crates:

```bash
cargo test --test http3_waf_boundary_guard
cargo test -p synvoid-http3
cargo test -p synvoid-waf
cargo test --lib --no-run
```

If HTTP/3 tests are feature-gated, use the correct feature set and document it in the implementation note.

If GitHub status checks are absent, state that no GitHub CI status was available and list the local commands run.

## Acceptance Criteria

This pass is complete when:

1. HTTP/3/WAF ownership rules are documented.
2. `crates/synvoid-http3` is confirmed to use only narrow WAF/protocol abstractions.
3. Any concrete HTTP/3 dependency on root WAF/app services is removed or explicitly documented as follow-up.
4. Request context construction parity is audited, improved, or documented with exact gaps.
5. WAF decision mapping between HTTP/1/2 and HTTP/3 is audited.
6. Streaming body WAF behavior is audited for HTTP/3.
7. A mechanical guardrail prevents obvious concrete service coupling from entering HTTP/3.
8. Focused tests pass or unavailable tests are documented.
9. No broad protocol rewrite or feature expansion is introduced.

## Notes for the Implementer

Keep this as a boundary cleanup. The desired architectural shape is simple:

> Worker/data-plane composition owns concrete services. WAF owns enforcement semantics. HTTP/3 owns protocol adaptation. HTTP/3 may ask a narrow WAF trait for decisions, but it must not own or construct WAF policy services.

If the audit finds HTTP/3 streaming WAF gaps, document them precisely. Do not convert this into a full streaming-body implementation unless the fix is already localized and low-risk.
