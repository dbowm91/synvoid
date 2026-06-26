# Phase 1 Plan: Root Ownership Closure and Dependency Entitlement

Status: detailed handoff plan.

Roadmap position: Phase 1 of `plans/roadmap.md`.

Primary goal: keep the root `synvoid` crate as the application/runtime composition crate, not the long-term owner of domain logic or unentitled dependencies.

This phase should be performed before further feature expansion. The repository already has a root module ledger and a root facade boundary guard. This pass makes those controls stricter and starts paying down the remaining `split_required` modules.

## Architectural Context

The root crate currently exports three categories of modules:

1. Root-owned composition/runtime modules, such as `commands`, `server`, `startup`, `supervisor`, `tcp`, `udp`, and `worker`.
2. Mixed modules that still contain implementation and need targeted extraction or ownership clarification.
3. Compatibility facades over dedicated crates.

`architecture/root_module_ledger.md` is the source of truth for this ownership model. `tests/root_facade_boundary_guard.rs` already prevents domain crates under `crates/` from importing root `synvoid::` paths.

The next risk is root dependency drift. Even if modules are extracted, root `Cargo.toml` can keep broad dependency ownership. This phase adds a dependency entitlement model so every direct root dependency has a documented reason.

## Non-Goals

Do not rewrite the heavy `server`, `http`, or `waf` modules in this phase.

Do not remove compatibility facades that external/internal callers still need unless the call sites are inventoried and migrated.

Do not change runtime behavior except where moving code requires import-path updates.

Do not introduce large new crates unless extraction is straightforward and clearly reduces root ownership.

## Deliverables

1. `architecture/root_dependency_ownership.md` listing every direct root dependency and its entitlement.
2. A guard test that fails if a direct root dependency is added without a ledger entry.
3. A `split_required` burn-down update in `architecture/root_module_ledger.md`.
4. Low-risk extraction or cleanup for at least two of: `auth`, `captcha`, `logging`, `platform`, `filter`.
5. Updated `AGENTS.md` notes if paths or ownership rules change.
6. Green targeted tests and profile checks listed below.

## Step 1: Create Root Dependency Entitlement Ledger

Create `architecture/root_dependency_ownership.md`.

Suggested schema:

```markdown
# Root Dependency Ownership Ledger

This file records why each direct dependency in the root `synvoid` package exists. The root crate may depend on a crate only when the dependency is needed by a root-owned composition/runtime module, a temporary compatibility facade, or a documented migration blocker.

Classification values:

- `composition_runtime`: needed by root-owned startup/server/supervisor/worker/process code.
- `compat_facade`: retained for root compatibility paths only.
- `migration_blocker`: should move to a dedicated crate after blocker is resolved.
- `test_or_tooling`: needed only for tests, examples, or developer tooling.
- `remove_candidate`: appears removable after verification.

| Dependency | Root owner module(s) | Classification | Feature gate | Reason | Next action |
|------------|----------------------|----------------|--------------|--------|-------------|
| tokio | server, supervisor, worker, startup | composition_runtime | default | async runtime and task orchestration | keep |
```

Populate it from the root `[dependencies]` section in `Cargo.toml`. Include path dependencies and third-party dependencies. Comments in `Cargo.toml` that already explain moved dependencies should be reflected as `remove_candidate` only if the dependency is still present and suspicious.

Pay special attention to these classes:

- Crypto/TLS: `rustls`, `tokio-rustls`, `aws-lc-rs`, `rustls-pki-types`, `subtle`, `zeroize`.
- QUIC/networking: `quinn`, `nix`, `ipnetwork`, `hickory-*`, `tokio-dstip`.
- Persistence: `rusqlite`, `memmap2`, `zip`, `walkdir`.
- Plugin/runtime: `libloading`, plugin crate paths, WASM-related dependency comments.
- Metrics/runtime: `metrics`, `metrics-exporter-prometheus`, `tracing-*`.
- Broad utility crates: `dashmap`, `parking_lot`, `moka`, `regex`, `aho-corasick`, `unicode-normalization`.

If a dependency is used only by a mixed module, classify it as `migration_blocker` rather than pretending it is permanently root-owned.

## Step 2: Add Dependency Ledger Guard

Add a test file such as `tests/root_dependency_ownership_guard.rs`.

The guard should parse the root `Cargo.toml` and the ledger file. A simple line-oriented parser is acceptable for this pass, but avoid overfitting to exact formatting.

Minimum behavior:

- Read root `Cargo.toml`.
- Extract direct dependencies under the root `[dependencies]` table only.
- Ignore `[workspace.dependencies]`, `[patch.crates-io]`, and nested crate manifests.
- Normalize dependency names where package rename syntax exists. For this guard, table keys are acceptable as the expected ledger names.
- Read `architecture/root_dependency_ownership.md`.
- Fail if any root dependency name is absent from the ledger table.
- Fail if the ledger contains an obvious placeholder such as `TBD`, `unknown`, or `fill me in`.

Example skeleton:

```rust
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn root_manifest_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_root_deps = false;

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_root_deps = trimmed == "[dependencies]";
            continue;
        }
        if !in_root_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _rest)) = trimmed.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                deps.insert(name.to_string());
            }
        }
    }

    deps
}

#[test]
fn root_dependencies_have_ownership_entries() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let deps = root_manifest_dependencies(&manifest);
    let mut missing = Vec::new();

    for dep in deps {
        let needle = format!("| {} |", dep);
        if !ledger.contains(&needle) {
            missing.push(dep);
        }
    }

    assert!(
        missing.is_empty(),
        "root dependencies missing ownership ledger entries:\n{}",
        missing.join("\n")
    );

    for forbidden in ["TBD", "unknown", "fill me in"] {
        assert!(
            !ledger.contains(forbidden),
            "root dependency ledger contains placeholder: {forbidden}"
        );
    }
}
```

This guard is intentionally simple. If it becomes noisy due to TOML edge cases, replace the parser with `toml` or `toml_edit` in a test-support context.

## Step 3: Burn Down Low-Risk `split_required` Modules

Start with modules that are small or self-contained according to `architecture/root_module_ledger.md`.

Recommended order:

1. `captcha`: self-contained SVG captcha generation/verification. Depends on theme. Candidate owner: `synvoid-challenge` or a new `synvoid-captcha` crate. Prefer `synvoid-challenge` if captcha is part of challenge flow and does not warrant its own crate.
2. `logging`: syslog configuration and logging types. Candidate owner: `synvoid-config` if mostly config types; otherwise root-owned `logging` can be downgraded to `keep_app_root` if it is purely process logging setup.
3. `platform`: platform enum/detection should move into `synvoid-platform` unless it depends on root-only behavior.
4. `filter`: protocol filtering traits/config should move to `synvoid-proxy` if used by TCP/UDP proxy behavior; otherwise keep root-owned with a narrower classification.
5. `auth`: larger, but described as depending only on `DrainFlag`. Candidate owner: new `synvoid-auth` or existing admin/control-plane crate. Do not start here unless the smaller extractions are done.

For each module touched:

- Inventory public items.
- Search call sites.
- Move domain types/functions to target crate.
- Leave root module as a compatibility facade when needed.
- Update imports in root and domain crates to use dedicated crate paths.
- Update `architecture/root_module_ledger.md` status.
- Add or update `AGENTS.override.md` in facade directories if this repo pattern is already used there.

## Step 4: Preserve Facade Boundary

Run and update `tests/root_facade_boundary_guard.rs` only if necessary. The allowlist should remain empty unless there is a documented, temporary blocker.

If a temporary allowlist is unavoidable, require:

- path substring,
- reason,
- linked ledger blocker,
- planned removal phase.

Do not add broad allowlists.

## Step 5: Update Root Module Ledger Guard if Needed

If new root modules are added or modules are converted to `pub use`, ensure `tests/root_module_ledger_guard.rs` still reflects the desired behavior. If that guard does not yet check classification values, extend it to reject unknown classification labels.

Suggested classification validation:

```rust
const VALID_CLASSIFICATIONS: &[&str] = &[
    "keep_app_root",
    "facade_existing_crate",
    "split_required",
    "legacy_or_stale",
];
```

The test should fail if the ledger table contains a classification outside this set.

## Step 6: Root Feature Profile Check

After dependency movement, verify feature gates. The most likely breakage is a dependency that was root-owned under default features but is also needed under `--no-default-features --features mesh` or `dns`.

Run:

```bash
cargo fmt
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo check
```

If a profile fails because an optional dependency is no longer feature-gated correctly, fix the feature mapping in root `Cargo.toml` and the target crate manifest rather than adding the dependency back unconditionally.

## Step 7: Documentation Updates

Update:

- `architecture/root_module_ledger.md` for every moved or reclassified module.
- `architecture/root_dependency_ownership.md` for any dependency added/removed/moved.
- `AGENTS.md` if file paths or ownership rules changed.
- `.opencode/skills/*` only if they contain stale paths for touched modules.

Do not leave stale path references. If a module moves, grep docs for old paths.

Useful search commands:

```bash
rg "src/captcha|crate::captcha|synvoid::captcha"
rg "src/logging|crate::logging|synvoid::logging"
rg "src/platform|crate::platform|synvoid::platform"
rg "src/filter|crate::filter|synvoid::filter"
rg "src/auth|crate::auth|synvoid::auth"
```

## Acceptance Criteria

This phase is complete when:

- `architecture/root_dependency_ownership.md` exists and covers every direct root dependency.
- `tests/root_dependency_ownership_guard.rs` fails for undocumented root dependencies.
- At least two low-risk `split_required` modules are extracted, reclassified, or reduced to pure facades.
- No domain crate under `crates/` imports `synvoid::` root paths.
- Root module ledger accurately describes every public root module.
- Feature profile checks pass for core, mesh, DNS, full mesh+DNS, and default.
- Any remaining `split_required` modules have concrete blockers and next actions.

## Handoff Notes for Smaller Models

Do not begin by editing `src/server/mod.rs`, `src/http/`, or `src/waf/`. Those are high-gravity areas for later phases.

Prefer tiny moves with strong tests. A successful phase can be valuable even if it only extracts `captcha` and `logging` plus adds the dependency entitlement guard.

When moving code, preserve public root compatibility paths unless all call sites are migrated and the ledger says the facade can be removed.

Keep guardrail allowlists empty unless there is no alternative.
