# Phase 40 Plan: YARA-X Security Upgrade Reopen After Resolver Unblock

Status: planned (2026-09-18).

Roadmap: `plans/runtime_dependency_blocker_followup_roadmap.md`.
Depends on: Phase 39.

Primary goal: finish the YARA-X portion of the Phase 36 security work after the minifier/Oxc resolver blocker is removed, using a YARA-X release whose own Wasmtime dependency is on a security-fixed line.

## Current decision constraint

Phase 39 should make current YARA-X releases resolvable, but resolvable is not the same as acceptable.

As researched on 2026-09-18:

- YARA-X 1.20.0 is the current release;
- it uses Wasmtime 45.0.3;
- YARA-X upstream PR #769 moves that dependency to Wasmtime 47.0.4 and raises YARA-X's MSRV from 1.93 to 1.94;
- the PR is open and not released;
- SynVoid's Rust 1.98.1 toolchain satisfies either MSRV;
- SynVoid's direct plugin runtime is already on Wasmtime 36.0.15 LTS and does not need to move for this phase.

Therefore:

> Do not land stock YARA-X 1.20.0 as the final Phase 40 state if it still resolves Wasmtime 45.0.3.

The goal is to leave the repository better than the Phase 38 graph, not merely newer.

## Part A — Refresh upstream status immediately before implementation

Check:

- latest YARA-X release;
- its exact `wasmtime` requirement;
- status/merge result of PR #769 or successor;
- Wasmtime security advisory fixed ranges;
- whether YARA-X has moved to Wasmtime 48 LTS or a newer supported line;
- current YARA-X MSRV.

Record exact versions and commit/release dates in the closeout.

## Part B — Preferred source selection

Use the first applicable branch below.

### Branch 1 — Official fixed YARA-X release

Preferred.

Select an official crates.io YARA-X release that:

- is >=1.19, so GHSA-2jx3-ff3v-j7jj is fixed;
- resolves Wasmtime at or above the fixed range for all advisories relevant to the enabled YARA-X feature set;
- is compatible with SynVoid's pinned Rust toolchain.

If YARA-X releases on Wasmtime 47.0.4+, accept the temporary dual-runtime graph:

```text
synvoid-plugin-runtime -> wasmtime 36.0.15 LTS
synvoid-yara -> yara-x -> wasmtime 47.x
```

Duplicate Wasmtime majors are not a failure if ownership is clear and both lines are security-supported/patched for their exposed capabilities.

If YARA-X instead moves to Wasmtime 48 LTS, use the official YARA release. Do not automatically move the plugin runtime to 48 in the same phase.

### Branch 2 — No official fixed YARA-X release yet

Default action is to keep the mitigated YARA-X 1.15 state briefly rather than land stock 1.20.0 with Wasmtime 45.0.3.

The current Phase 36 boundary already prevents remote/mesh compiled bytes from reaching `Rules::deserialize`, which reduces urgency enough to prefer an official release when practical.

If an immediate upgrade is required for a new security reason:

- create a project-controlled minimal fork of the official YARA-X release;
- apply only the upstream-reviewed Wasmtime/MSRV compatibility change represented by PR #769 or its successor;
- pin the fork by immutable revision;
- run YARA-X upstream tests plus SynVoid's full YARA boundary suite;
- create the same owner/review/removal metadata required for the Phase 39 temporary fork.

Do not depend directly on a contributor's personal PR branch.

## Part C — Upgrade `synvoid-yara`

Update:

```text
crates/synvoid-yara/Cargo.toml
Cargo.lock
```

and any exact engine compatibility identifiers.

At minimum update:

```rust
YARA_ENGINE_VERSION
```

Audit `COMPILED_FORMAT_VERSION`:

- engine change only => engine version bump may be sufficient;
- SynVoid artifact envelope/meaning change => bump format version too.

Old engine artifacts must reject deterministically.

Do not restore remote compiled-artifact execution merely because the new YARA-X deserializer is fixed.

## Part D — Preserve the Phase 36 trust model

The final execution model remains:

> remotely distributed YARA rules execute from approved source compiled locally inside the execution boundary.

Re-run guards proving:

- mesh does not call `yara_x::Rules::deserialize`;
- upload does not call it directly;
- remote compiled bytes are ignored/opaque;
- local source update compiles and swaps atomically;
- invalid source retains/fails according to configured policy;
- any local compiled artifact path has authenticated provenance and version binding.

A YARA-X upgrade does not relax these requirements.

## Part E — Recompute the Wasmtime graph

After the YARA-X upgrade:

```bash
cargo tree -i yara-x --workspace
cargo tree -i wasmtime --workspace
cargo tree -e features -i wasmtime@36.0.15 --workspace
cargo tree -e features -i wasmtime@<yara-line> --workspace
cargo tree -i wasmtime-wasi --workspace
cargo tree -i wasi-filesystem --workspace
cargo audit
cargo deny check
```

Required outcome:

- Wasmtime 40.0.4 is gone;
- direct Wasmtime 36 remains owned by `synvoid-plugin-runtime`;
- the YARA transitive Wasmtime line is identified separately;
- no accidental `wasmtime-wasi` filesystem capability appears without explicit review.

If YARA-X resolves Wasmtime 48 LTS, record that as a future convergence opportunity only. A plugin-runtime 36 -> 48 migration requires its own containment/performance validation.

## Part F — Advisory and policy cleanup

Remove advisory ignores that existed only for the retired YARA-X 1.15 / Wasmtime 40 path.

Update:

- `.cargo/audit.toml`;
- `deny.toml`;
- dependency-security authority docs;
- repo guards that inspect YARA-X/Wasmtime versions;
- any Phase 36/38 closeout documents that still state the blocker is active.

Do not delete unrelated exceptions.

Do not describe a capability-unreachable advisory as patched; distinguish version remediation from reachability mitigation.

## Part G — YARA behavior verification

Re-run/extend:

- bundled rules compile;
- source validation;
- local compile/reload;
- old-engine artifact rejection;
- upload clean/malicious/indeterminate policy;
- timeout behavior;
- concurrency/queue limits;
- large-file and windowed scanning;
- archive interaction;
- mesh source rule propagation;
- jail execution;
- provenance/signature checks;
- failed reload retains previous rules;
- malformed remote compiled bytes are never deserialized.

Capture parser/compiler diagnostic changes caused by the YARA-X upgrade rather than suppressing them globally.

## Part H — Performance and footprint

Measure before/after:

- representative rule compilation time;
- clean scan throughput;
- match-heavy scan throughput;
- scanner reload latency;
- YARA dependency subtree size;
- workspace build time attributable to the newer Wasmtime/Cranelift tree;
- release binary size.

The expected cost of carrying Wasmtime 36 plus the YARA line must be explicit.

Do not force convergence merely to improve crate-count aesthetics unless measurements show a material footprint problem.

## Part I — Remove the Phase 39 temporary minifier fork when possible

Phase 40 should re-check `minify-html` upstream.

If an official release now:

- moves off Oxc 0.95;
- no longer introduces the bumpalo 3.19 conflict;
- passes the Phase 39 parity corpus;

then replace the temporary fork with the official release in this phase.

If no such release exists, keep the fork pinned and retain its removal trigger. Do not conflate the temporary minifier workaround with YARA ownership.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo check -p synvoid-yara --all-targets
cargo test -p synvoid-yara
cargo test -p synvoid-upload
cargo test -p synvoid-static-files
cargo test -p synvoid-repo-guards
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo audit
cargo deny check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

## Acceptance criteria

Phase 40 is complete only when:

- YARA-X is >=1.19;
- its resolved Wasmtime line is security-fixed for the relevant advisories/capabilities;
- Wasmtime 40.0.4 is absent;
- Phase 36 remote-source-only execution remains enforced;
- old engine artifacts reject deterministically;
- YARA tests and full verification are green;
- obsolete advisory ignores are removed;
- direct plugin Wasmtime remains clearly separated from YARA's transitive runtime;
- any temporary source fork has explicit removal metadata;
- docs no longer say the YARA-X upgrade is bumpalo-blocked.

## Rejection criteria

Reject an implementation that:

- lands stock YARA-X 1.20.0 with known-affected Wasmtime 45.0.3 as the final state merely because it resolves;
- points SynVoid at an unreviewed contributor fork;
- moves the plugin runtime off Wasmtime 36 LTS solely for version matching;
- reintroduces remote compiled-rule deserialization;
- deletes security exceptions without proving the affected package/path is gone;
- claims convergence benefit without measuring dependency/binary impact.
