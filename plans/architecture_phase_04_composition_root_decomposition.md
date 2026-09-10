# Phase 04 — Composition-Root Decomposition Without New Crates

Status: implementation handoff plan
Baseline: root-module ledger, WAF/HTTP ownership convergence documents

## Objective

Reduce maintenance cost and change coupling inside the large, legitimate application composition roots without changing subsystem ownership or creating more crates.

Primary targets are the root `UnifiedServer` wiring, `WafCore` composition, and admin router construction. Their size is not itself a defect; the defect to address is that unrelated subsystem changes can require editing broad monolithic constructors/functions and can therefore create accidental lifecycle/order regressions.

## Scope

Primary targets:

- `src/server.rs` (`UnifiedServer` composition)
- `src/waf/mod.rs` and root WAF composition helpers
- `src/admin/mod.rs` router construction
- directly adjacent root-private adapters/builders
- architecture documentation describing ownership and lifecycle order

Do not move root-owned application services into domain crates. Do not add `synvoid-server-core`, `synvoid-composition`, or similar crates.

## Work plan

### 1. Measure edit/lifecycle boundaries before refactoring

For each target, map the current logical sections and dependencies. Identify:

- construction-only dependencies;
- long-lived runtime handles;
- optional feature-gated services;
- startup order dependencies;
- shutdown/drain ownership;
- cross-links that exist only because values are built in one large function;
- sections that can be extracted as private pure/near-pure builders without changing ownership.

Document the proposed boundaries before code movement.

### 2. Decompose `UnifiedServer` by subsystem assembly

Prefer root-private functions/types such as conceptual equivalents of:

- listener/runtime assembly;
- WAF/security service assembly;
- backend/service assembly;
- optional mesh/DNS/plugin assembly;
- admin/observability assembly;
- shutdown/drain assembly.

Names should follow actual repository concepts rather than these placeholders.

Each helper should return a narrow typed bundle needed by later composition, not a giant bag-of-everything. Keep initialization order visible at the top-level `UnifiedServer` constructor/start method.

Avoid introducing builder patterns where a private function is sufficient.

### 3. Decompose `WafCore` internally, not across ownership boundaries

`WafCore` remains root application composition over the canonical `synvoid-waf` engine and root-owned services.

Extract coherent private assembly stages for groups such as detector/policy setup, runtime trackers, threat/rule-feed integration, rate/traffic controls, and render/backends only where the dependency graph supports it.

Do not recreate domain implementations already canonical in `synvoid-waf`. Do not move GeoIP/tarpit/theme/upload/worker application dependencies into the domain crate merely to shrink `src/waf/mod.rs`.

Add constructor-level tests where feasible to prove feature-gated assembly yields the same enabled/disabled capabilities.

### 4. Partition admin route construction by route family

`build_router_from_state` currently registers a large number of routes in one composition function. Split route registration into root-private family routers/functions, for example:

- core/read-only observability/stats;
- sites/config;
- system/process;
- probes/threat/rules;
- optional mesh/DNS/ICMP/plugin/serverless families;
- auth/public routes;
- WebSocket routes;
- SPA/static delivery.

Preserve one obvious final composition point where middleware ordering and `/api` nesting are visible.

Do not duplicate `AdminState` or middleware stacks per family. Middleware/auth/CSRF semantics must remain equivalent.

### 5. Make feature gates local and auditable

Feature-specific assembly should be encapsulated near the relevant family builder so `#[cfg]` branches do not fragment the top-level lifecycle.

A disabled feature should either omit its service/route family or return an explicitly empty optional bundle; avoid placeholder runtime objects that appear enabled.

### 6. Preserve initialization and shutdown semantics with characterization tests

Before moving code, add/extend tests for:

- service/capability presence under default and selected feature profiles;
- admin route family presence/absence;
- startup failure propagation from representative subsystem builders;
- shutdown/drain ordering where observable;
- WAF dependency wiring required for request-path behavior.

Refactoring is complete only if these tests remain behaviorally unchanged.

### 7. Set local complexity budgets, not arbitrary LOC gates

Do not fail the phase because a composition root remains >N lines. Instead require:

- top-level functions describe orchestration at one abstraction level;
- independent route/subsystem families can be modified without editing unrelated registration blocks;
- private bundles have coherent ownership and limited fields;
- no helper becomes a second composition root hidden in another file.

Record final module responsibilities in the relevant architecture documents.

## Rejection criteria

Reject an implementation that:

- creates new crates solely to reduce file size;
- moves application-owned services into reusable domain crates;
- hides initialization order behind generic dependency injection/service-locator machinery;
- replaces one large function with many pass-through helpers that provide no conceptual boundary;
- duplicates state/middleware to partition the admin router;
- changes feature behavior as an incidental refactor;
- broadens public API for private composition convenience.

## Acceptance criteria

1. `UnifiedServer`, `WafCore`, and admin routing retain their documented root ownership.
2. Their top-level orchestration functions operate at a clear subsystem/family level rather than interleaving unrelated low-level setup.
3. Independent subsystem/route changes have localized edit surfaces.
4. Feature gates remain behaviorally equivalent and are easier to audit.
5. No new crate is introduced for composition code.
6. Characterization/integration tests demonstrate preserved startup, capability, route, and request-path behavior.
7. Architecture documents describe the final internal boundaries and continue to identify one canonical implementation owner per domain.

## Verification

```text
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
```

Use targeted admin/WAF/server tests after each extraction step rather than performing the whole decomposition in one unreviewable move.
