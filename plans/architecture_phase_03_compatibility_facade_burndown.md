# Phase 03 — Compatibility-Facade Retirement Policy and First Burn-Down

Status: implementation handoff plan
Baseline: `architecture/root_module_ledger.md`, `architecture/final_surface_audit.md`

## Objective

Reduce duplicated public/import surface created by root compatibility facades while preserving deliberate compatibility guarantees. The goal is not to remove every facade; it is to make every remaining facade intentional, documented, and governed by a retirement rule.

Most current overlap is alias overlap rather than duplicate implementation. This phase must preserve that distinction and avoid reopening already-settled ownership boundaries.

## Current state

The root-module ledger classifies many modules as `facade_existing_crate`, including app-server/auth/challenge/config/DNS/filter/GeoIP/HTTP3/integrity/listener/mesh/metrics/proxy/router/protocol/static-files/theme/tunnel/upload/upstream/VPN and related surfaces. Many are one-line or otherwise thin `pub use` facades and are technically safe, but they provide two discoverable paths for the same canonical implementation.

The final public-surface audit calls these paths transitional, but the repository does not currently define a general condition under which “transitional” becomes retained, deprecated, or removed.

## Scope

- `src/lib.rs`
- every root module classified `facade_existing_crate`
- workspace-internal imports of those root paths
- docs/examples/tests that teach root compatibility imports
- `architecture/root_module_ledger.md`
- `architecture/final_surface_audit.md`
- `architecture/root_module_burndown_report.md`
- relevant `AGENTS.override.md` files

Do not alter modules classified `keep_app_root` merely to reduce the number of root modules.

## Work plan

### 1. Build a facade disposition matrix

For every `facade_existing_crate` row, record:

- canonical crate/path;
- root facade path;
- facade shape: pure re-export, type alias, local adapter/submodule, local tests;
- number and location of workspace consumers;
- documentation/examples using the root path;
- whether the root path is intentionally part of a supported external API;
- feature-gating differences between facade and canonical crate;
- proposed disposition.

Allowed dispositions:

- `retain_stable_compat`: deliberate supported compatibility surface;
- `deprecate_then_remove`: compatibility path has plausible external consumers and needs a migration window;
- `remove_now`: zero-value internal alias with no compatibility requirement;
- `adapter_keep_app_root`: not actually a pure compatibility facade; root-specific adapter remains but canonical domain implementation stays in the crate.

Add this matrix to an architecture document before deleting paths.

### 2. Define retirement policy

A root facade is eligible for immediate removal only if all are true:

- zero workspace consumers after direct imports are migrated;
- no user-facing docs/examples intentionally advertise it;
- no stable public-API commitment documents it;
- no root-only adapter/feature behavior is hidden behind it;
- canonical crate path is already public and ergonomic.

If external compatibility is uncertain, prefer `#[deprecated(note = "use ...")]` or retain the facade rather than silently breaking consumers.

Do not add deprecation attributes where they generate unmanageable internal warnings; migrate internal callers first.

### 3. Migrate internal consumers to canonical crates

Within domain crates and reusable modules, imports should prefer the dedicated canonical crate rather than traversing through the root application crate.

Root composition may keep root aliases where they genuinely improve application wiring, but reusable crates must not depend on compatibility paths that obscure ownership.

Use repository-wide search to prove each migration before removal.

### 4. Perform the first low-risk burn-down

Start with pure re-export facades that have no internal consumers and no documented compatibility value. Do not batch mixed adapters into this pass.

Likely candidates should be determined from the matrix, not assumed from names. Preserve feature-gated facade behavior until equivalent canonical imports are proven under the same feature profiles.

### 5. Normalize docs and agent guidance

Update README/API/developer/architecture docs so new code examples consistently use canonical crate paths where appropriate.

Where a facade is intentionally retained, document it explicitly as compatibility rather than canonical ownership. This prevents agents/contributors from treating both paths as peer implementations.

### 6. Add an ownership regression guard

Extend existing root-module ownership tests or add a narrow test that:

- parses the ownership ledger/disposition list;
- fails when a module classified as a pure facade gains substantive local implementation;
- fails when a removed/deprecated facade is reintroduced without ledger update;
- permits documented root adapters.

The guard should be simple/static and fast. Avoid building a code-generation framework for this purpose.

## Rejection criteria

Reject an implementation that:

- removes compatibility paths solely because a dedicated crate exists;
- moves `keep_app_root` application composition into domain crates;
- creates replacement aliases under different names without reducing surface area;
- breaks feature-gated builds by changing import ownership without equivalent gates;
- makes public API removals without documentation/migration evidence;
- turns the root-module ledger into aspirational state that does not match code.

## Acceptance criteria

1. Every `facade_existing_crate` entry has an explicit final or transitional disposition with rationale.
2. Workspace-internal domain code prefers canonical crate imports.
3. At least the proven zero-value facade subset is removed or deprecated; no requirement exists to delete deliberate compatibility aliases.
4. No duplicate implementation is introduced as part of facade cleanup.
5. Documentation teaches one canonical implementation owner per subsystem.
6. A regression guard prevents pure facades from silently accumulating implementation.
7. Default and supported no-default/feature builds remain green.

## Verification

```text
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
```

Before each removal, run repository search for both the module path and representative exported symbols. Record any intentionally retained external compatibility assumptions in the disposition matrix.
