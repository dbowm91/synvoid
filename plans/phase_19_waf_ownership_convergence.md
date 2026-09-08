# Phase 19 Plan: WAF Ownership Convergence and Root Composition Reduction

Status: detailed handoff plan.

Roadmap position: Track 3, Phase 19 of `plans/roadmap.md`.

Primary goal: make `synvoid-waf` the unambiguous owner of reusable WAF policy/detection logic while reducing `src/waf/` to root application composition, compatibility exports, and narrowly justified adapters.

## Context

The repository already has a substantial `crates/synvoid-waf` containing attack detection, bot handling, endpoints, flood protection, mitigation, primitives, rate limiting, sanitization, threat logic, traffic shaping, traits, and violation tracking. At the same time, `src/waf/` still contains large implementations and similarly named modules, and `src/waf/mod.rs` owns a large `WafCore` that wires rate limiting, bot detection, endpoint blocking, challenges, authentication, attack detection, threat level, violation tracking, IP feeds, probe tracking, traffic shaping, ASN tracking, and flood protection.

The result is a mixed ownership state: some root modules are compatibility/adapters, while others remain canonical implementations. This phase completes the ownership decision without turning the domain crate into a dependency sink for the entire application.

Phase 17 must establish the canonical enforcement contract first. Phase 18 should remove authentication/challenge ownership blockers before this phase begins.

## Constraints

- Request-path capability boundaries from Track 1 remain binding.
- `synvoid-waf` must not depend on the root `synvoid` crate.
- Do not move supervisor, admin, mesh transport, filesystem lifecycle, or process composition into `synvoid-waf` merely to eliminate root LOC.
- Preserve hot-path behavior and avoid additional per-request allocations/locks.
- Preserve compatibility root exports according to stability policy.
- Remove dead/no-op compatibility logic where compatibility policy permits; otherwise mark it explicitly deprecated and keep it out of the active hot path.

## Step 1: Build a file-level WAF ownership matrix

Inventory every entry under `src/waf/` against `crates/synvoid-waf/src/`.

For each root file/submodule classify it as:

- exact/thin facade over crate functionality
- root adapter around crate functionality
- duplicate implementation
- reusable WAF domain logic that belongs in `synvoid-waf`
- application composition that should remain root-owned
- control-plane/threat-intel integration that belongs in another dedicated crate
- stale/dead compatibility code

At minimum include:

- `adapter.rs` / `adapters.rs`
- `asn_tracker.rs`
- `attack_detection/`
- `endpoints.rs`
- `flood/`
- `ip_feed.rs`
- `probe_tracker.rs`
- `ratelimit.rs` and `ratelimit/`
- `rule_feed.rs`
- `threat_intel/`
- `threat_level/`
- `traffic_shaper/`
- `violation_tracker/`
- the `WafCore` and `WafCoreConfig` definitions in `src/waf/mod.rs`

Record the matrix in `architecture/waf_ownership_convergence.md`. Do not rely on matching filenames as evidence of duplication; compare responsibility and callers.

## Step 2: Remove duplicate implementations first

Where root and crate implementations describe the same domain behavior, choose the dedicated crate as canonical unless a dependency blocker is documented.

For each migrated component:

1. move or retain canonical implementation in `synvoid-waf`;
2. migrate tests with it;
3. replace root implementation with a re-export or thin adapter;
4. migrate internal domain-crate callers to `synvoid_waf::*`;
5. preserve root compatibility exports only as required.

Priority candidates are components that already exist under both roots, especially attack detection, endpoints, flood, rate limiting, traffic shaping, violation tracking, and probe tracking.

Do not preserve two implementations merely because their APIs differ. Normalize the API or create one narrow adapter.

## Step 3: Split `WafCore` into domain engine and application composition

After Phase 18, reassess every field of `WafCore` and `WafCoreConfig`.

Classify fields into:

- core request-policy engine state
- external service capability/adapter
- application lifecycle/composition state
- unrelated subsystem state that should be queried through a narrow interface

The preferred end state is:

- `synvoid-waf` owns reusable request-policy evaluation and its internal detector state;
- root owns construction/wiring of runtime-specific services and compatibility adapters;
- WAF evaluation consumes narrow capabilities, not concrete root managers.

If the full `WafCore` can move cleanly after auth/challenge extraction, move it and retain a root facade/type alias only as required. If some application-only wiring must remain, rename/split it so the root type is visibly composition (for example `AppWaf`/`WafRuntimeAdapter`) rather than remaining the canonical policy engine by accident.

Do not optimize for zero root LOC; optimize for one owner per concept.

## Step 4: Delete hot-path placeholder checks

`WafCore::check_request_full` currently contains a `check_block_store` call whose implementation always returns `None` because block-store admission moved to the worker composition root.

Remove this dead check from the active WAF pipeline once compatibility tests prove it is unnecessary. The worker admission boundary should remain the sole active block-store request check.

Likewise audit root compatibility methods such as:

- `check_early` that always returns pass
- block-mutation compatibility shims that are no-ops

For each shim:

- remove it if internal/private compatibility no longer requires it;
- otherwise mark it deprecated and ensure no production call site relies on it;
- add a guard preventing new call sites.

A compatibility method that silently does nothing must not look like an active enforcement API.

## Step 5: Apply the Phase 17 decision pipeline

Move the canonical enforcement classification/source/reason handling into the WAF engine.

Refactor detector mappings so each detector produces either:

- evidence/internal result only, then a policy adapter maps it to enforcement, or
- a typed enforcement candidate carrying source and reason.

Keep expensive detector scheduling explicit. Preserve justified terminal short-circuits, but ensure the action reducer/precedence contract governs conflicts.

Replace repeated free-form metrics source strings with the canonical source enum/labels.

## Step 6: Decouple threat/control-plane state

Root WAF currently references threat level, violation tracking, feeds, ASN/GeoIP, and distributed/request services. For each dependency decide whether it is:

- WAF domain state that belongs in `synvoid-waf`,
- a service capability that should be passed through an existing narrow trait,
- a control-plane subsystem that should remain outside the WAF engine.

Do not let distributed mesh state become directly authoritative inside request-policy code. The existing request-path policy gate/capability boundary remains the integration point.

## Step 7: Configuration ownership

Move WAF-specific configuration DTOs/builders to the canonical crate/config crate where appropriate, but do not duplicate repository-wide config structures.

`WafCoreConfig` should stop being a catch-all constructor containing concrete root managers. Prefer:

- data-only WAF configuration
- an explicit dependency bundle of narrow service interfaces where needed

Avoid giant constructors with application-owned concrete types.

## Step 8: Guard the final ownership model

Update:

- `architecture/root_module_ledger.md`
- `architecture/root_module_burndown_report.md`
- `architecture/root_dependency_ownership.md`
- `architecture/final_surface_audit.md`
- `architecture/waf.md`
- relevant `AGENTS.override.md`

Add/update guards so:

- `synvoid-waf` never imports root compatibility modules
- `src/waf` cannot regain duplicate implementations for crate-owned modules
- root facade modules remain thin where classified as facades
- deprecated no-op compatibility methods acquire no new production callers

## Acceptance criteria

Phase 19 is complete when:

- every file/submodule under `src/waf/` has a documented owner classification
- reusable WAF detector/policy logic has one canonical implementation
- duplicate root implementations for crate-owned components are removed
- the active WAF request path contains no known always-`None`/always-pass placeholder check
- block-store enforcement remains in the worker/admission composition boundary rather than moving back into WAF mutation logic
- `WafCore` is either owned by `synvoid-waf` or reduced/renamed to clearly root-owned composition with narrow interfaces
- `WafCoreConfig` no longer couples reusable WAF logic to avoidable root concrete managers
- Phase 17 enforcement source/reason/precedence semantics are used consistently
- `src/waf` can be reclassified from `split_required` to either `facade_existing_crate` or `keep_app_root` with a precise rationale
- root and crate WAF tests, request-path guards, and relevant benchmarks pass without material regression

## Rejection criteria

Reject an implementation that:

- merely moves files while preserving duplicate behavior under new names
- makes `synvoid-waf` depend on root `synvoid`
- moves mesh/control-plane mutation authority into the request WAF
- restores block-store writes to WAF convenience methods
- replaces explicit typed interfaces with `Arc<dyn Any>`/service locators
- changes enforcement precedence accidentally through refactoring
- keeps production call sites on known no-op compatibility shims

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo test -p synvoid-waf
cargo test -p synvoid-http
cargo test --test request_path_capability_boundary_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test manual_enforcement_provenance_guard
```

Also run the existing WAF/normalization/attack-detection/rate-limit benchmarks relevant to moved code and record before/after results for Phase 24.
