# Phase 17 Plan: Canonical Request Enforcement Decision Contract

Status: detailed handoff plan.

Roadmap position: Track 3, Phase 17 of `plans/roadmap.md`.

Primary goal: make request enforcement compositional and deterministic by defining one canonical vocabulary for enforcement class, source/provenance, reason, and precedence across WAF, rate limiting, bot detection, flood protection, honeypot/challenge, block state, HTTP dispatch, and protocol adapters.

## Why this phase exists

SynVoid already has a canonical `synvoid_waf::WafDecision`, but the repository still contains multiple adjacent decision/result vocabularies with overlapping semantics:

- `synvoid_waf::WafDecision`
- `synvoid_proxy::protocol::WafAction`
- `RateLimitResult`
- `FloodDecision`
- bot-detection results
- streaming WAF decisions
- HTTP/body-policy errors and dispatch outcomes
- block-store admission checks in the worker composition root

`src/waf/mod.rs::check_request_full` also encodes policy precedence implicitly through early returns: block store placeholder, rate limit, endpoint block, honeypot, bot protection, flood protection, then attack detection. That call order currently functions as policy. It should be represented explicitly and tested as policy rather than remaining an incidental property of implementation order.

This phase does not merge all detectors into one subsystem. Detectors remain independently testable components. The goal is a small shared decision contract through which their outputs compose.

## Constraints

- Preserve the existing public/runtime behavior unless an existing conflict is explicitly identified and tested.
- Do not add a new workspace crate solely for this DTO. Prefer the lowest-level existing crate that does not create a dependency cycle.
- Do not force response-rendering payloads such as challenge HTML into a transport-neutral enum if that creates cross-layer coupling.
- Do not permit request-path code to gain block-store mutation capability; the existing request-path capability boundary remains binding.
- Preserve fail-closed semantics for malformed/unsupported enforcement outcomes.
- Avoid allocations on the common allow path.
- Do not introduce dynamic policy scripting or a generic rules DSL as part of this phase.

## Step 1: Build an enforcement-result inventory

Create `architecture/enforcement_decision_contract.md` and inventory every enum/type that can affect request disposition. At minimum inspect:

- `crates/synvoid-waf/src/primitives.rs`
- `crates/synvoid-proxy/src/protocol/trait_def.rs`
- `src/waf/mod.rs`
- `src/waf/ratelimit.rs` and `crates/synvoid-waf/src/ratelimit/`
- flood, bot, endpoint, honeypot, challenge, attack-detection, and streaming paths
- `crates/synvoid-http/src/waf_decision.rs`
- `crates/synvoid-http/src/http3_waf_dispatch.rs`
- `crates/synvoid-http/src/body_policy.rs`
- worker block-store/admission composition

For each type record:

| Type | Owner | Meaning | Terminal? | Carries response payload? | Canonical/adapter/internal |
|------|-------|---------|-----------|---------------------------|----------------------------|

Do not delete domain-specific detector results merely because they eventually map to an enforcement outcome. Detector results may carry useful evidence that is not an enforcement action.

## Step 2: Introduce a transport-neutral enforcement classification

Add a small canonical classification to an existing low-level crate after confirming dependency direction. Preferred location is `synvoid-core` if doing so does not introduce higher-level dependencies; otherwise keep the contract in `synvoid-waf` and document why.

The contract should distinguish at least:

- `Allow`
- `Observe` / log-only evidence where applicable
- `Challenge`
- `Stall`
- `Tarpit`
- `Block`
- `Drop`

Do not embed rendered HTML, cookies, or protocol-specific response objects in the classification. Existing `WafDecision` may remain the rich response directive while exposing a lossless `class()` mapping.

Add typed provenance such as `EnforcementSource` with stable categories for:

- block store
- rate limit
- endpoint policy
- honeypot
- bot policy
- flood protection
- attack detection/rules
- streaming/body scan
- operator/manual policy where applicable
- distributed/mesh-derived enforcement where applicable

Add a bounded/stable reason-code representation. Human-readable strings may remain attached for logs/operator UX, but metrics and tests should use a stable reason/source code rather than free-form text.

## Step 3: Define precedence as data and tests

Document the reducer precedence explicitly. Preserve current effective behavior where possible, but make conflict semantics deliberate.

The default terminal ordering should be evaluated and fixed in tests. A reasonable starting point is:

`Drop > Block > Tarpit > Stall > Challenge > Observe > Allow`

However, do not adopt that ordering mechanically if a current policy intentionally chooses a different action for a specific pair. Record every exception explicitly.

The reducer must satisfy:

- order independence for equivalent sets of candidates
- idempotence (`reduce(x, x) == x`)
- an allow/observe candidate cannot erase a terminal enforcement candidate
- a lower-precedence candidate cannot weaken a higher-precedence candidate
- provenance/reason for the selected action is deterministic
- ties have a deterministic documented rule

Add property-style/table-driven tests covering every pair of enforcement classes and representative multi-candidate sets.

## Step 4: Separate evidence production from action reduction

Refactor `WafCore::check_request_full` incrementally so policy-producing checks can return typed candidates rather than relying on incidental early-return order.

Do this in small passes. Do not parallelize expensive detectors indiscriminately; request latency and resource use still matter. It is acceptable for a terminal high-priority check such as a known block-store denial to short-circuit execution. The difference is that the reason for short-circuiting must be part of the documented reducer/phase policy rather than an undocumented call-order artifact.

Use an explicit staged pipeline, for example:

1. admission state that may safely short-circuit (pre-existing block/blackhole)
2. cheap local policy checks
3. challenge/bot/rate/flood candidates
4. expensive attack/body inspection when still required
5. deterministic reduction
6. response rendering/dispatch

Document which stages may short-circuit and why.

## Step 5: Remove duplicate transport action semantics

Audit `synvoid_proxy::protocol::WafAction` against the canonical classification and `WafDecision`.

Preferred outcomes, in order:

1. replace it with the canonical classification if dependency direction is clean;
2. otherwise make it an explicitly transport-local adapter with exhaustive `From`/mapping tests;
3. do not retain two independently evolving public enums with the same semantic variants.

Apply the same rule to HTTP/streaming adapter types: domain-specific results may remain, but mappings to the canonical enforcement class must be exhaustive and tested.

## Step 6: Normalize observability around the contract

Replace ad-hoc source strings where practical with the canonical source/reason vocabulary.

At minimum preserve or improve:

- `synvoid_request_enforcement_source_total`
- action/disposition counters
- reason-code counters with bounded cardinality
- terminal outcome logging

Do not place IPs, URLs, user agents, or arbitrary rule text into metric labels.

## Step 7: Add architectural guards

Add a focused guard test that prevents new request-disposition enums from being introduced casually in request-path crates. The guard should allow documented detector-internal result types but flag new enums containing overlapping terminal action variants such as `Allow`, `Block`, `Challenge`, `Drop`, `Tarpit`, or `Stall` unless they are registered as adapters in `architecture/enforcement_decision_contract.md`.

Keep the guard simple and source-oriented; do not build a Rust parser.

## Acceptance criteria

Phase 17 is complete when:

- `architecture/enforcement_decision_contract.md` inventories all request-disposition/result types and names one canonical enforcement classification.
- Enforcement source and bounded reason codes are typed and shared across the main request path.
- Precedence/conflict semantics are explicit and covered by exhaustive pairwise reducer tests.
- `WafCore::check_request_full` no longer relies solely on undocumented source ordering for policy semantics.
- Block-store/request-path mutation boundaries remain unchanged or stricter.
- `synvoid_proxy::protocol::WafAction` is either removed in favor of the canonical contract or reduced to an explicitly tested adapter.
- HTTP/streaming mappings are exhaustive and fail closed for unsupported outcomes.
- Metrics use bounded source/action/reason vocabulary.
- Common allow-path behavior does not acquire material new allocation or locking overhead.
- Existing WAF/HTTP/request-path guard suites remain green.

## Rejection criteria

Reject an implementation that:

- combines every detector into one monolithic engine merely to share an enum
- introduces a new general-purpose policy language
- lets `Allow` overwrite a previously selected terminal denial
- makes precedence depend on hash-map iteration or task completion order
- moves block-store mutation capability into the request WAF
- puts arbitrary strings into high-cardinality metrics
- creates a new crate solely to hold a handful of DTOs without demonstrating a dependency need
- changes challenge/block/drop semantics without focused compatibility tests

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check
cargo test -p synvoid-waf
cargo test -p synvoid-http
cargo test -p synvoid-proxy
cargo test --test request_path_capability_boundary_guard
cargo test --test manual_enforcement_provenance_guard
```

Add focused tests for the reducer, adapter mappings, and source/reason metrics. Run existing request/WAF benchmarks before and after the refactor and record any material regression for Phase 24 follow-up.
