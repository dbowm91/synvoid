# Phase 37 Plan: Direct Wasmtime Migration to Supported LTS

Status: planned (2026-09-16).

Roadmap: `plans/runtime_dependency_security_followup_roadmap.md`.
Depends on: Phase 36 complete or sufficiently stable that the final YARA-X/Wasmtime transitive graph is known.

Primary goal: move the direct SynVoid plugin runtime off Wasmtime 42.0.2 + git patch and onto the supported Wasmtime 36 LTS line, target 36.0.15 or newer 36.0.x security patch, without weakening plugin containment or guest compatibility.

This is an intentional migration from a newer unsupported normal release to an older supported LTS release.

## Current state

The direct plugin runtime currently declares:

```toml
wasmtime = { version = "42.0.2", features = ["component-model"] }
```

and the workspace uses a `[patch.crates-io]` git source for Wasmtime 42.0.2.

Security baseline facts:

- 42.0.2 is affected by RUSTSEC-2026-0269;
- SynVoid currently proves `wasmtime-wasi` is absent, so the vulnerable filesystem sandbox code is not linked/reachable;
- upgrading directly to >=46.0.3 was previously blocked by the workspace `bumpalo =3.19.0` constraint from `minify-html` -> Oxc;
- Wasmtime 36 is an LTS line supported through 2027-08-20;
- RUSTSEC-2026-0269 is fixed in Wasmtime 36.0.14 and later;
- 36.0.15 is the current 36 LTS patch release as of this plan.

The migration is worthwhile even though the current vulnerable capability is absent: it removes an unsupported direct runtime line, clears the direct 0269 finding, removes a git patch, and puts the most security-sensitive embeddable runtime on a line with guaranteed security backports.

## Part A — Prove resolver compatibility before touching runtime code

Create an isolated resolver experiment or temporary branch change that replaces direct 42.0.2 with 36.0.15 while keeping the current workspace dependency set.

Required proof:

```bash
cargo generate-lockfile
cargo tree -p synvoid-plugin-runtime --depth 2
cargo tree -i wasmtime@36.0.15 --workspace
cargo tree -e features -i wasmtime@36.0.15 --workspace
```

Confirm the `minify-html`/Oxc `bumpalo =3.19.0` pin does not block Wasmtime 36.

Do not proceed on an assumed semver relationship; record the actual resolved `bumpalo` and Wasmtime subtree.

## Part B — Build an API-compatibility inventory

Inventory every direct Wasmtime API used by:

```text
crates/synvoid-plugin-runtime/src/wasm_runtime.rs
crates/synvoid-plugin-runtime/src/instance_pool.rs
crates/synvoid-plugin-runtime/src/pool.rs
crates/synvoid-plugin-runtime/src/spin/runtime.rs
crates/synvoid-plugin-runtime/src/test_fixtures.rs
benches/bench_wasm.rs
```

At minimum verify parity for:

- `Config` construction;
- Cranelift optimization configuration;
- `memory_init_cow`;
- `max_wasm_stack`;
- fuel consumption and `Store::set_fuel`;
- epoch interruption and `Store::set_epoch_deadline`;
- `Engine::increment_epoch` if used;
- `ResourceLimiter` memory/table callbacks;
- `Module`, `Instance`, `Linker`, `Store`, `Memory`, `TypedFunc`;
- component-model `Component` / component linker APIs actually used;
- instance pooling and store reinitialization;
- trap/error classification relied upon by policy code.

Classify each difference as:

1. source-compatible;
2. mechanical API adaptation with identical semantics;
3. semantic behavior difference requiring tests;
4. missing required capability.

A missing required containment capability is a hard blocker. Do not emulate it with a weaker local mechanism merely to complete the migration.

## Part C — Land the LTS version migration first, with behavior parity

Change direct runtime ownership to the selected 36.0.x patch line.

Update all direct Wasmtime consumers, including the root benchmark/dev dependency if applicable.

The first landing target should preserve the current effective feature/proposal behavior as closely as possible. Do not combine a major runtime-version change with aggressive guest-feature removal unless tests prove there is no behavior change.

Required invariants after the migration:

- fuel remains enabled for sandboxed production tiers;
- epoch interruption remains the wall-clock backstop;
- memory/table growth limits remain enforced;
- host-call budgets remain bounded;
- plugin signature/trust-tier policy is unchanged;
- WASI filesystem remains absent;
- unsafe native extensions remain opt-in and separate from the WASM sandbox;
- hot reload/lifecycle generation semantics are unchanged;
- Spin runtime behavior remains compatible with supported manifests.

## Part D — Remove the git patch and source exception

If the direct 36 LTS migration succeeds using crates.io:

1. remove the Wasmtime `[patch.crates-io]` entry;
2. remove the Wasmtime git source from `deny.toml` `allow-git` if no other git dependency requires it;
3. update comments in `Cargo.toml`, `deny.toml`, `.cargo/audit.toml`, `SECURITY.md`, `AGENTS.md`, and architecture evidence that refer to direct 42.0.2;
4. update repo guards that pin the direct runtime version/source;
5. prove `cargo tree` has no direct 42.0.2 path.

Do not leave the old git allowlist "for convenience" once the source is gone.

## Part E — Minimize the direct Wasmtime feature surface, conditionally

Current dependency syntax enables Wasmtime default features in addition to `component-model` unless the manifest explicitly disables defaults.

After the 36 LTS migration passes full parity, capture:

```bash
cargo tree -e features -p synvoid-plugin-runtime
cargo tree -e features -i wasmtime@36.0.x --workspace
```

Then identify the minimum explicit Wasmtime features required by SynVoid.

Likely candidates to evaluate include:

- `std`;
- `runtime`;
- `cranelift`;
- `component-model`;
- any feature strictly required by current guest proposal compatibility.

Do **not** assume this exact set is sufficient. Wasmtime feature composition differs across major lines and must be derived from the resolved 36.0.x manifest plus SynVoid tests.

Potentially removable default capabilities may include caching/profiling/WAT parsing/GC/threading/parallel compilation or other features that SynVoid does not intentionally expose. Each removal requires a guest compatibility test or explicit statement that the proposal is unsupported by SynVoid.

If feature minimization creates substantial compatibility work, split it into a separate follow-up rather than delaying the security version migration.

## Part F — Add runtime compatibility fixtures

Create or extend fixtures that exercise the behavior SynVoid promises, not merely Wasmtime construction.

At minimum:

- request filter pass/block/challenge;
- response transform;
- handler output path;
- guest allocator/free contract;
- memory growth at/beyond configured limit;
- table growth at/beyond configured limit;
- fuel exhaustion;
- epoch deadline interruption;
- host-call capability denial;
- host-call timeout;
- malformed/invalid module rejection;
- module with missing required exports;
- hot reload generation replacement;
- pooled instance reset/state isolation;
- component-model path if production-supported;
- Spin manifest execution path.

Tests must distinguish policy failures from runtime traps so the migration cannot silently alter failure classification.

## Part G — Performance and footprint evidence

Capture before/after on the same host/toolchain where practical:

- module compile latency;
- cold instantiation latency;
- pooled invocation latency;
- filter request hot path;
- transform path;
- memory footprint per pooled instance;
- release binary size;
- clean rebuild time for the plugin runtime subtree.

Use `benches/bench_wasm.rs` as the starting point but add missing containment-sensitive cases if needed.

A modest performance delta is acceptable for moving to a supported LTS line, but large regressions require explanation and either mitigation or an explicit product tradeoff.

## Part H — Direct advisory disposition

After migration, verify:

```bash
cargo audit
cargo deny check advisories
cargo tree -i wasmtime@42.0.2 --workspace
cargo tree -i wasmtime@36.0.x --workspace
```

Direct 42.0.2 must be absent.

The direct plugin-runtime path should no longer require a RUSTSEC-2026-0269 ignore because Wasmtime 36.0.14+ is patched.

Do not remove an ignore that is still required by the transitive YARA-X Wasmtime version; Phase 38 will normalize the final multi-version advisory record.

## Decision gate if 36 LTS cannot satisfy the runtime

If implementation proves that a required production capability used by SynVoid was introduced after Wasmtime 36 and cannot be reproduced with equivalent or stronger security semantics:

1. stop the migration;
2. document the exact missing API/capability and call sites;
3. retain the current capability-absence guard for 42.0.2 temporarily;
4. re-evaluate Wasmtime 48 LTS only after the `bumpalo` conflict is removed or the minifier dependency is replaced through a separately justified plan;
5. do not move to another unsupported normal Wasmtime line as a compromise.

This gate must be evidence-based. Compile errors alone are not proof of missing capability if a documented API adaptation exists.

## Acceptance criteria

Phase 37 is complete only when:

- the direct plugin runtime resolves to Wasmtime 36.0.14+ LTS, target 36.0.15+;
- direct 42.0.2 is absent;
- plugin containment/resource semantics are preserved or strengthened;
- WASI filesystem remains absent;
- the Wasmtime git patch and git source allowlist are removed if no longer used;
- plugin, Spin, pooling, hot-reload, and benchmark fixtures pass;
- direct 0269 advisory exposure is eliminated by version, not merely ignored;
- any feature minimization is proven by compatibility tests and measured footprint evidence;
- the final dependency graph and security docs distinguish direct 36 LTS from the separate YARA-X transitive Wasmtime line.

## Rejection criteria

Reject an implementation that:

- disables fuel/epoch/resource limiting to regain API compatibility;
- enables `wasmtime-wasi` or filesystem preopens without a separate security design;
- moves to another unsupported normal Wasmtime release;
- retains the git patch after moving to a crates.io LTS release without a concrete reason;
- removes default Wasmtime features without testing guest proposal compatibility;
- claims the transitive YARA-X Wasmtime advisory is fixed by changing only the direct runtime;
- conflates lower version number with lower security support.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo check -p synvoid-plugin-runtime --all-targets --all-features
cargo test -p synvoid-plugin-runtime --all-features
cargo test -p synvoid-serverless --all-features
cargo test -p synvoid-jail-runtime --all-features
cargo bench --bench bench_wasm --no-run
cargo tree -p synvoid-plugin-runtime --depth 2
cargo tree -e features -i wasmtime@36.0.x --workspace
cargo tree -i wasmtime@42.0.2 --workspace
cargo audit
cargo deny check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo check --no-default-features
```

Record the landed Wasmtime patch version, explicit feature set, resolver/bumpalo result, removed git source, benchmark deltas, and any API adaptation in the closeout evidence.
