# Phase 15 Plan: Transitional Root Module Burn-Down Track

Status: detailed handoff plan.

Roadmap position: Track 2, Phase 15 of `plans/roadmap.md`.

Primary goal: reduce the remaining `split_required` root modules without destabilizing the hardened runtime, request-path, plugin, admin, and mesh boundaries.

## Context

The hardening roadmap classified root modules and added dependency ownership guards, but several root modules remain transitional. This is acceptable for Track 1, but long-term maintainability requires a measured burn-down path. This phase starts that burn-down with small extraction/reclassification passes.

Remaining `split_required` modules include:

- `admin`
- `auth`
- `challenge`
- `http`
- `http_client`
- `platform`
- `plugin`
- `tarpit`
- `tls`
- `utils`
- `waf`

## Non-Goals

Do not extract `http` or `waf` first.

Do not break root compatibility facades.

Do not move request-path code in a way that weakens boundary guards.

Do not create circular dependencies between root and domain crates.

Do not delete public root exports without deprecation/stability notes.

## Deliverables

1. Prioritized root module burn-down inventory.
2. Detailed extraction plans for the first selected module cluster.
3. At least two modules extracted or reclassified per implementation pass.
4. Updated `architecture/root_module_ledger.md`.
5. Updated `architecture/root_dependency_ownership.md`.
6. Updated `architecture/final_surface_audit.md`.
7. Compatibility facade tests where needed.
8. Guard updates preventing regression.

## Phase A: Re-Inventory Root Modules

Run:

```bash
find src -maxdepth 2 -type f -name '*.rs' | sort
rg "split_required|facade_existing_crate|keep_app_root|legacy_or_stale" architecture/root_module_ledger.md
rg "pub mod|pub use" src/lib.rs
```

Create or update a burn-down table:

```markdown
| Module | Current classification | LOC | Root-only deps | Target | Risk | Suggested action | Blocker |
|--------|------------------------|-----|----------------|--------|------|------------------|---------|
```

Estimate LOC with:

```bash
wc -l src/auth.rs src/platform.rs src/tarpit.rs src/tls.rs src/waf/mod.rs
```

Adjust paths to actual module layout.

## Phase B: Prioritize Extraction Candidates

Use this order unless inventory proves otherwise:

1. `platform` — likely extract/reclassify to `synvoid-platform`.
2. `utils` — move shared pieces to `synvoid-utils`, leave root-only helpers root-owned.
3. `tarpit` — keep handler root-owned, move reusable logic to `synvoid-tarpit`.
4. `tls` — split root `HttpsServer` composition from `synvoid-tls` primitives.
5. `auth` — candidate for `synvoid-auth`, but may touch admin heavily.
6. `plugin` — composition root should stay root; pure plugin runtime belongs in crate.
7. `http_client` — separate QUIC tunnel dispatch root composition from client crate.
8. `challenge` — move manager or classify root orchestration.
9. `admin` — extract after Phase 12 legacy endpoint closure.
10. `waf` — large and sensitive; plan separately.
11. `http` — largest/high-risk; plan after WAF/request boundaries settle.

## Phase C: Select First Cluster

Recommended first cluster:

- `platform`
- `utils`
- `tarpit`

Reason: lower risk than `http`/`waf`/`admin`, likely fewer request-path semantics, and useful for reducing root entropy.

For each selected module:

1. Identify reusable domain logic.
2. Move reusable logic to existing dedicated crate where possible.
3. Keep root-only orchestration in root with `keep_app_root` classification.
4. Preserve `src/<module>/mod.rs` as compatibility facade if public root path exists.
5. Update imports in root code to dedicated crate where possible.
6. Add/adjust tests.

## Phase D: Extraction Pattern

Preferred pattern:

```rust
// src/platform/mod.rs
//! Compatibility facade for `synvoid-platform`.
//! New code should import `synvoid_platform` directly.

pub use synvoid_platform::*;
```

For mixed modules:

```rust
// src/tarpit/mod.rs
//! Root-owned tarpit request handler plus compatibility exports.

pub use synvoid_tarpit::{MarkovChain, TarpitConfig};

mod handler;
pub use handler::TarpitHandler;
```

Then ledger classification can become either:

- `facade_existing_crate` if pure facade,
- `keep_app_root` if only root composition remains,
- `split_required` with narrower blocker if some mixed code remains.

## Phase E: Dependency Ledger Updates

After every extraction:

- Remove direct root dependencies no longer needed.
- Add moved dependencies to target crate `Cargo.toml`.
- Update `architecture/root_dependency_ownership.md`.
- Run root dependency guard.

Commands:

```bash
cargo tree -p synvoid --depth 1
cargo tree -p synvoid-platform --depth 1
cargo tree -p synvoid-utils --depth 1
cargo tree -p synvoid-tarpit --depth 1
```

## Phase F: Guardrails

Existing guards to run:

```bash
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
```

Add guard improvements if needed:

- prevent newly extracted crate from importing `synvoid::*`,
- ensure facade files remain thin,
- ensure `split_required` rows include blocker text,
- ensure moved modules have `AGENTS.override.md` if needed.

Possible new guard: `tests/root_facade_thinness_guard.rs`.

Behavior:

- allow pure doc comments and `pub use`,
- fail if a `facade_existing_crate` module contains non-trivial logic.

## Phase G: Tests

For each moved module:

- Move or duplicate unit tests into target crate.
- Add compatibility test that root facade re-export still compiles.
- Run target crate tests.

Example:

```bash
cargo test -p synvoid-platform
cargo test -p synvoid-utils
cargo test -p synvoid-tarpit
cargo test -p synvoid --lib platform
cargo test -p synvoid --lib tarpit
```

## Phase H: Documentation Updates

Update:

- `architecture/root_module_ledger.md`
- `architecture/root_dependency_ownership.md`
- `architecture/final_surface_audit.md`
- `architecture/semver_stability_policy.md` if public/stability labels change
- `AGENTS.md` if commands/guard counts change

Add `architecture/root_module_burndown_report.md` after implementation.

Report structure:

```markdown
# Root Module Burn-Down Report

## Summary
## Modules Changed
## Dependencies Moved/Removed
## Facades Preserved
## Tests Run
## Remaining split_required Modules
## Next Recommended Cluster
```

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh,dns
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test request_path_capability_boundary_guard
cargo test -p synvoid-platform
cargo test -p synvoid-utils
cargo test -p synvoid-tarpit
```

Adjust crate names to actual touched crates.

## Acceptance Criteria

This phase is complete when:

- At least two transitional modules are extracted or reclassified with precise rationale.
- Root compatibility paths continue to compile.
- No domain crate imports root `synvoid::*`.
- Root dependency ledger is current.
- Final surface audit reflects new stability/classification status.
- Remaining `split_required` modules have updated blockers and next priorities.

## Handoff Notes

Do not start with `http`, `waf`, or `admin`. Those are high-risk and should get their own detailed plans after lower-risk burn-down proves the pattern.
