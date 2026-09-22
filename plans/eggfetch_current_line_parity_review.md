# Eggfetch Current-Line Parity Review (follow-up decision gate)

Status: research review complete enough to open implementation qualification; final adoption decision is delegated to Phase 58. This plan remains the historical follow-up gate from Phase 47 and must not be used as proof that production migration has already passed.

Implementation roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Qualification gate: `plans/phase_58_eggfetch_0_2_qualification_and_compatibility.md`.

Context: Phase 47 deferred a public `synvoid-http-client` support decision until a newer eggfetch line could be evaluated, deciding against the then-current 0.1.4-era baseline. That threshold has now been crossed. The Phase 34 / Phase 47 0.1.4-era matrix is dated decision history and must not be used as current evidence. `synvoid-http-client` remains internal while Phases 58-61 prove or reject consolidation.

Research baseline: SynVoid `main` at `e3026667c23e6e0e92ee30d13c53baf2e68c5c77` (2026-09-22).

Current upstream reviewed: `eggfetch-core 0.2.0`, tag `v0.2.0`, released 2026-09-22.

## Research conclusion

The current eggfetch line is materially different from the 0.1.4 line evaluated by Phase 34. Source/API review of the 0.2.0 tag found that the major functional blockers have moved:

- generic native request execution now accepts arbitrary `http_body::Body<Data = Bytes>`;
- `NativeHttpService` exposes the same generic-body contract through Tower;
- native responses preserve DATA/trailer frames;
- TLS configuration accepts an explicit Rustls `CryptoProvider`;
- hostname and certificate verification are independently controlled, with a chain-preserving hostname-skip verifier;
- UDS is a first-class advanced-routing capability;
- resolved/pinned targets have bounded route-specific client reuse;
- phase-aware timeout handling is richer than the old comparison assumed;
- MSRV is Rust 1.89.

This is sufficient to justify implementation qualification, not sufficient to declare adoption complete. The remaining hard questions are now compatibility and measured behavior rather than obvious missing primitives.

In particular, `synvoid-http-client` exports concrete Hyper-based aliases and root re-exports them. A migration that changes those concrete type identities could regress API compatibility even if all current workspace call sites compile. Phase 58 therefore owns an exact export/compatibility inventory before any production migration.

## Goal

Decide on executable current evidence: adopt eggfetch 0.2.0 behind a narrow SynVoid policy/compatibility layer, or retain the current transport with a documented blocker.

No new generic HTTP crate without explicit gap evidence. Do not migrate as a bookkeeping side effect.

## Scope

Phase 58 must evaluate at least:

- TLS backend/provider parity, including SynVoid aws-lc/PQ requirements;
- HTTP/1.1 and HTTP/2 behavior used by SynVoid;
- generic/streaming request bodies, including WAF mid-stream and H3-originated bodies;
- frame/trailer preservation;
- direct Unix-domain-socket routing;
- connection pooling and resolved-target reuse;
- timeout semantics through response-body completion;
- certificate-chain versus hostname-verification control;
- custom CA/SNI behavior;
- size/error/response-body limits;
- dependency footprint and duplicate Hyper/Rustls feature/version impact;
- API maturity/MSRV/support burden;
- exact compatibility obligation of current `synvoid-http-client` exports;
- whether production can use eggfetch while any concrete legacy facade remains compatibility-only.

## Method

1. Pin and qualify exactly `eggfetch-core 0.2.0` with a minimal native H1/H2 + Rustls feature set.
2. Re-run the Phase 34 capability matrix as executable tests wherever practical.
3. Add black-box/differential parity tests before any migration step.
4. Inventory every exported `synvoid-http-client` symbol and classify concrete type identity/source-compatibility requirements.
5. Record current evidence in `architecture/eggfetch_0_2_compatibility_matrix.md`; do not rewrite the Phase 34 historical record.
6. Proceed to Phase 59 only on an explicit go decision.

## Acceptance

This follow-up gate is considered research-complete when the implementation roadmap exists and Phase 58 has a concrete executable qualification specification. The actual adoption gate is not satisfied until Phase 58 records:

- current-line matrix with exact version/date/baseline;
- parity/security/dependency evidence;
- compatibility classification;
- an explicit go/no-go result.

The campaign then continues under:

- `plans/phase_59_eggfetch_native_transport_adapter.md`;
- `plans/phase_60_eggfetch_consumer_migration_and_legacy_transport_retirement.md`;
- `plans/phase_61_eggfetch_transport_qualification_and_closeout.md`.

## Non-goals

- No publication of `synvoid-http-client` merely because eggfetch can be adopted.
- No SynVoid-specific demands placed on eggfetch; only generally reusable upstream gaps justify upstream work.
- No public concrete type/signature churn disguised as an implementation change.
- No moving proxy retry/upstream-selection/WAF/cache policy into eggfetch.
- No outbound HTTP/3 requirement introduced as part of this consolidation.
