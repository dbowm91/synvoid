# Phase 106 Plan: Honeypot Application-Neutral Boundary Preparation

Status: **ACTIVE / READY**.

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).

Owner: honeypot/deception / architecture.

## Goal

Make `synvoid-honeypot` an application-neutral library boundary while keeping
it in the SynVoid repository for this phase. Remove unnecessary SynVoid-specific
dependencies and make the remaining embedding points explicit so Phase 107 can
decide standalone extraction from evidence rather than file layout.

No new repository or publication occurs in this phase.

## Current state

The crate already owns the cohesive deception runtime:

- listener/runner lifecycle;
- protocol detection and service banners;
- static/template/vulnerable/AI responders;
- AI concurrency/turn/provider-failure budgets;
- SQLite persistence and bounded writer path;
- port rotation;
- payload-retention policy;
- indicator extraction/scoring;
- injected `HoneypotThreatPublisher`.

Its manifest has only three SynVoid dependencies:

- `synvoid-config-model`;
- `synvoid-http-client`;
- `synvoid-utils`.

The current config surface is also ambiguous:

- `synvoid_honeypot::config::PortHoneypotConfig` is the rich runtime model;
- `synvoid_config_model::honeypot_port::HoneypotPortConfig` is a separate,
  smaller application configuration model and is directly held by the
  controller.

The implementation must first resolve this ownership mismatch.

## Workstream A — inventory and freeze behavior

Before moving types, inventory every external/root consumer of:

- `PortHoneypotConfig`;
- `HoneypotPortConfig`;
- controller construction/reconfiguration;
- runner construction;
- responder construction;
- storage paths;
- threat-intel publisher;
- AI provider constructors.

Build a compatibility matrix for:

- persisted TOML/JSON field names/defaults;
- runtime defaults;
- stable-port behavior;
- disabled/template/local-model/external-provider modes;
- payload-retention defaults;
- mesh publication enablement;
- admin mutation/reload behavior.

No config field may become ignored merely because ownership moves.

## Workstream B — establish one runtime-owned configuration vocabulary

Make the honeypot crate own the reusable runtime configuration types.

Preferred direction:

- runtime mechanism types remain under `synvoid_honeypot::config`;
- SynVoid's `synvoid-config-model` retains only application-facing persisted
  DTOs needed by `MainConfig`/schema generation;
- a narrow, exhaustive adapter translates persisted SynVoid DTOs into the
  honeypot-owned runtime config;
- the controller stores/accepts the runtime-owned type rather than directly
  storing a `synvoid-config-model` type.

Do not simply move the rich runtime struct into `synvoid-config-model`. That
would invert ownership in the wrong direction.

If the two current config surfaces represent genuinely different concepts,
rename them so the distinction is explicit and provide one adapter. Avoid two
public types whose names differ only by word order.

Golden config tests must prove persisted SynVoid configuration remains
compatible.

## Workstream C — remove `synvoid-utils`

Inventory each actual `synvoid-utils` use.

For generic primitives:

- use std directly where equivalent;
- own tiny time/bounds helpers locally when the semantics are part of the
  honeypot;
- inject clocks only where deterministic testing benefits.

Do not create a new shared crate to move trivial helpers.

Acceptance target: no normal dependency from `synvoid-honeypot` to
`synvoid-utils`.

## Workstream D — remove `synvoid-http-client` from the core boundary

AI-provider egress must not make the deception engine depend on SynVoid's
application HTTP compatibility layer.

Define a narrow transport boundary suitable for the actual provider calls, for
example an async JSON request capability with:

- method/URL;
- bounded headers/body;
- deadline/cancellation;
- bounded response body;
- typed transport/status failure.

Choose one implementation strategy from evidence:

1. inject a transport trait and keep all concrete HTTP clients outside the core;
2. use the reusable Eggfetch API directly in an optional provider integration
   module if doing so materially reduces adapter code without importing
   SynVoid-specific policy.

Do not expose `synvoid_http_client::HttpClient`,
`EggfetchUpstreamClient`, or SynVoid TLS config in the reusable public API.

Preserve current provider timeout, response-size, circuit-breaker and secret
redaction semantics.

## Workstream E — observability boundary

The current crate directly emits `metrics` and `tracing`.

For repository extraction readiness:

- stable metric names may remain implementation details;
- no consumer should be required to install a particular exporter;
- tracing fields must not leak payloads/API keys/provider secrets;
- evaluate feature-gating metrics if it materially lowers the standalone graph,
  otherwise retain the facade dependency and document it.

Do not invent a callback abstraction solely to remove two lightweight facade
crates.

## Workstream F — storage/privacy contract

Make the storage contract understandable without SynVoid documentation.

Document and test:

- retention modes: none/hash-only/truncated/full;
- default retention;
- truncation/hash semantics;
- maximum queue/batch/payload sizes;
- SQLite file behavior and failure handling;
- whether credentials/payloads are ever persisted;
- cleanup/retention execution;
- behavior under writer saturation.

No extraction-readiness claim is allowed while payload privacy semantics remain
implicit.

## Workstream G — dependency and boundary guards

Add a guard preventing reintroduction of high-level SynVoid dependencies into
`synvoid-honeypot`.

At minimum, after this phase the crate must not normally depend on:

- `synvoid-config`;
- `synvoid-config-model`;
- `synvoid-core`;
- `synvoid-mesh`;
- `synvoid-http-client`;
- root `synvoid`.

If the implementation retains one for a concrete reason, Phase 106 cannot close
as extraction-ready preparation until the exception is explicitly adjudicated.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-honeypot --profile ci
cargo check -p synvoid-honeypot --all-features
cargo test -p synvoid-config-model --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Add focused config golden tests, provider-transport fakes, storage-saturation
tests, and package-outside-workspace checks needed by the changed boundary.

## Acceptance criteria

- one unambiguous honeypot runtime config owner exists;
- SynVoid persisted config compatibility is proven;
- `synvoid-honeypot` no longer depends on config-model/http-client/utils unless
  a narrow exception is explicitly proven necessary;
- mesh/threat publication remains injected and application-owned;
- provider budgets, secret redaction, retention and storage failure semantics are
  preserved;
- package builds/tests outside the workspace apart from explicitly parent-owned
  guard tests;
- no public-support promise is made yet.

## Rejection criteria

Reject implementation that:

- moves configuration fields while silently changing defaults;
- makes the standalone library depend on SynVoid's root/config/mesh runtime;
- swaps HTTP implementations while weakening timeout/body/TLS policy;
- places API keys in serializable/loggable public state;
- treats moving files as extraction readiness without standalone package proof;
- creates an external repository in this phase.
