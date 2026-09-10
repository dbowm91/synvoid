# Track 3 Post-Closure Corrective Plan

Status: complete (2026-09-09). Closure evidence: `architecture/track3_post_closure_corrective_report.md`. Final closeout HEAD: `206726706dc66a556829585673b18c8e17370b46`.

The body below is the executed handoff specification, preserved as historical implementation guidance.

Scope: narrow verification/documentation truthfulness pass after Track 3 (Phases 17–24) was implemented and the canonical routine CI passed on `main` at `23949197311f1066abd4bc622c43cada615b1425`.

Primary goal: close the remaining evidence/documentation drift without reopening the architecture-convergence track or expanding CI complexity. This pass should make the repository's current-state claims match the actual implementation, run the broader verification contracts once against the final Track 3 tree, finish the one remaining high-value config-parser fuzz gap, and disposition the stale `serder` compatibility module explicitly.

## Why This Corrective Pass Exists

Track 3 landed successfully: the root ownership ledgers report zero active `split_required` modules, the jail path is operational, distributed-state semantics are documented and tested, and the current single-job GitHub Actions workflow passes `cargo xtask verify`.

The remaining issues are closure-quality issues rather than architecture defects:

1. `plans/roadmap.md` is internally inconsistent: its bottom status says Track 3 is complete through Phase 24, while its header and "Current Architectural Position" still describe Track 3 as planned and repeat pre-Track-3 gaps such as mixed root ownership and jail IPC stubs.
2. `architecture/ci_fuzz_failure_injection.md` and `architecture/phase_14_fuzz_execution_report.md` still describe a `fuzz-smoke`/`nightly-qualification.yml` CI topology that no longer exists. The actual repository has only `.github/workflows/ci.yml`, and the frozen verification contract treats fuzz smoke as manual.
3. Phase 24 recorded the three new fuzz targets at 300 bounded runs, while the repository's documented standard command is `-runs=1000`.
4. The final Track 3 HEAD has a passing routine `cargo xtask verify` GitHub Actions run, but the broader `cargo xtask verify-full` and `cargo xtask verify-release` contracts have not been recorded specifically against the final Track 3 revision.
5. Config parse/validation fuzzing remains the only explicitly listed high-value parser target not implemented.
6. `src/serder.rs` remains a deprecated/stale root module whose useful behavior is effectively documentation plus an `rkyv` re-export. The repository should either remove it under the pre-1.0 stability policy or state a concrete compatibility reason and removal horizon.

## Non-Goals

- Do not create Track 4 or Phase 25 for this cleanup unless implementation discovers a new architectural defect.
- Do not redesign enforcement, HTTP, WAF, admin, plugin, sandbox, mesh, or distributed-state architecture.
- Do not add another CI matrix, nightly workflow, benchmark gate, or permanent fuzz job.
- Do not merge crates as part of this pass.
- Do not rewrite historical plans/results merely because they describe the state that existed when they were written. Historical artifacts should be marked/superseded where needed, not retroactively rewritten into ahistorical documents.
- Do not claim release readiness if `verify-full` or `verify-release` fails; classify and fix real failures first.

## Workstream A: Reconcile Current-State Roadmap and Architecture Claims

### A1. Fix `plans/roadmap.md` current-state drift

Update the roadmap header so it states that Tracks 1–3 are complete and this corrective closure is the only active handoff item.

Replace the stale "Current Architectural Position" text with the actual post-Track-3 state:

- canonical enforcement contract exists;
- auth/challenge are canonical crate owners with root facades;
- WAF/HTTP mixed ownership is resolved into explicit composition-vs-domain boundaries;
- admin/plugin ownership is explicit;
- sandbox jail IPC is operational;
- distributed-state contract exists;
- zero `split_required` modules remain;
- routine CI passes on the final Track 3 commit;
- only corrective verification/documentation residuals remain.

Do not alter historical phase descriptions except where a current-state sentence incorrectly claims a completed phase is still pending.

### A2. Reconcile fuzz/CI documentation with the actual workflow

The current workflow inventory is authoritative: `.github/workflows/` contains only `ci.yml`, and that workflow runs `cargo xtask verify` on Ubuntu.

Update current architecture/release documentation so it no longer claims active `fuzz-smoke`, `nightly-qualification.yml`, dedicated tarpit/mesh jobs, or per-PR fuzz execution when those files/jobs do not exist.

At minimum inspect and reconcile:

- `architecture/ci_fuzz_failure_injection.md`
- `architecture/phase_14_fuzz_execution_report.md`
- `architecture/release_hardening_report.md`
- `docs/testing/verification-contract.md`
- `AGENTS.md`
- any non-historical docs found by the searches below

Use repository-wide searches:

```bash
rg -n "fuzz-smoke|nightly-qualification|main-comprehensive|release-qualification" . \
  --glob '!plans/**' --glob '!target/**'
rg -n "17 fuzz targets|20 fuzz targets|fuzz.*CI|CI.*fuzz" architecture docs AGENTS.md
rg -n "Track 3 is planned|ready for implementation|jail IPC is not implemented|split_required" \
  plans/roadmap.md architecture AGENTS.md docs
```

Classification rule:

- current architecture/operator docs must describe the repository as it exists now;
- historical result/plan files may retain historical topology, but must contain a short "superseded by current verification contract" note if readers could mistake them for current operational instructions.

### A3. Add a compact corrective closure report

Create:

`architecture/track3_post_closure_corrective_report.md`

It should contain only reproducible current-state evidence:

- corrective implementation commit/revision;
- workflow inventory;
- routine CI status/link or commit SHA;
- `verify-full` result;
- `verify-release` result;
- fuzz target execution table;
- config fuzz target disposition;
- `serder` disposition;
- remaining accepted residuals, if any.

Do not duplicate the full Track 3 performance or architecture reports.

## Workstream B: Bring Phase 24 Fuzz Evidence to the Declared Standard

Run the three new Track 3 targets using the repository's documented bounded smoke count:

```bash
cargo +nightly fuzz run http_chunked_framing -- -runs=1000
cargo +nightly fuzz run jail_ipc_frame_decode -- -runs=1000
cargo +nightly fuzz run http_routing_matcher -- -runs=1000
```

Record for each target:

- exact command;
- final revision;
- cargo-fuzz/nightly versions if readily available;
- run count;
- pass/crash/hang status;
- minimized crash path if applicable.

If a deterministic crash is found:

1. minimize the input;
2. add a normal regression test under the owning crate or the existing Track 3 closure suites;
3. fix the bug;
4. re-run the target for 1000 executions;
5. record the fix commit in the corrective report.

Do not weaken the documented standard to 300 merely to match the prior evidence. If an environment cannot complete 1000 bounded runs, record the exact blocker and leave the item open.

## Workstream C: Execute the Broader Final-HEAD Verification Contracts

The current routine GitHub Actions run proves only `cargo xtask verify`. Track 3 changed the workspace graph, added `synvoid-auth`, changed package boundaries, and touched release/public surfaces, so execute the broader contracts against the final corrective revision.

Required commands:

```bash
cargo xtask verify-full
cargo xtask verify-release
```

`verify-full` must cover:

- mesh-only compilation;
- DNS-only compilation;
- mesh+DNS compilation;
- broad workspace nextest suite;
- doctests.

`verify-release` must validate the release/package qualification contract, especially the newly added/moved crate surfaces.

Failure handling:

- real product regression -> fix in this pass;
- stale expectation/harness defect -> classify with evidence, then fix the harness if it blocks the canonical contract;
- environment-only blocker -> document exact command/error and do not mark closure complete;
- do not exclude a failing product test solely to make the closure pass green.

After fixes, re-run the complete failing contract, not only the individual failing test.

## Workstream D: Close Config Parse/Validation Fuzzing

Config TOML is operator-controlled external input and remains the only explicitly listed high-value parser boundary without a fuzz target.

### D1. Prefer an in-memory production parsing seam

Do not perform filesystem I/O on every fuzz iteration.

Inspect the current production loaders:

- `crates/synvoid-config/src/main_config.rs` (`MainConfig::from_file`)
- `crates/synvoid-config/src/site/` (`SiteConfig::from_file`)
- `crates/synvoid-config/src/validation.rs`

If parsing and validation are only reachable through `from_file`, extract a minimal pure helper such as:

```rust
pub fn from_toml_str(input: &str) -> Result<Self, ConfigError>
```

or a package-private equivalent shared by `from_file` and the fuzz target.

The production file loader must delegate to the same parsing/validation seam; do not create a fuzz-only parser that can drift from production.

### D2. Add one bounded target

Preferred target name:

`config_parse_validation`

Register it in `fuzz/Cargo.toml` and drive both main/site parsing without unbounded allocation or filesystem/network access. A leading selector byte can choose the parser path if one target can cover both cleanly.

Expected behavior for arbitrary bytes:

- invalid UTF-8/TOML -> typed parse error;
- structurally valid but invalid config -> typed validation error;
- valid config -> successful parse/validation;
- no panic, abort, uncontrolled filesystem access, socket creation, or unbounded loop/allocation.

Run:

```bash
cargo +nightly fuzz run config_parse_validation -- -runs=1000
```

Update the fuzz inventories/counts only after the target exists and the bounded run is recorded.

If a pure production parsing seam would require a disproportionate API redesign, document the blocker in the corrective report rather than building an inaccurate fuzz-only surrogate.

## Workstream E: Explicitly Disposition `serder`

`src/serder.rs` is currently classified `legacy_or_stale`; it is predominantly migration documentation plus a feature-gated `rkyv` re-export. `src/lib.rs` still exports it as `pub mod serder`, while canonical serialization already lives at `synvoid_utils::serialization` / the root `serialization` re-export.

Run:

```bash
rg -n "\bserder\b|synvoid::serder|crate::serder" . --glob '!target/**'
rg -n "\brkyv\b" Cargo.toml crates src tests architecture docs
cargo check --features rkyv
```

Preferred outcome if there are no real downstream/internal consumers:

- remove `src/serder.rs`;
- remove `pub mod serder;` from `src/lib.rs`;
- preserve the canonical serialization path;
- move any still-useful migration guidance into architecture documentation if it is still accurate;
- update `architecture/root_module_ledger.md`, `architecture/final_surface_audit.md`, `architecture/release_hardening_report.md`, and related docs so `serder` is removed rather than indefinitely listed as a candidate.

If compatibility evidence justifies retention:

- mark the module explicitly deprecated in code/docs;
- name the supported replacement path;
- state the planned removal milestone/version;
- add a small guard so no new internal code imports it.

Do not retain it only because deletion changes a public root path; the repository is pre-1.0 and already documents root facades as transitional. Apply the actual semver/stability policy rather than assuming removal is forbidden.

## Workstream F: Final Truthfulness Sweep and Closure

After Workstreams A–E:

```bash
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

Then run focused searches:

```bash
rg -n "Track 3 is planned|ready for implementation" plans/roadmap.md architecture docs AGENTS.md
rg -n "fuzz-smoke|nightly-qualification.yml" architecture docs AGENTS.md \
  --glob '!**/*historical*' --glob '!plans/**'
rg -n "jail IPC is not implemented|jail-process stubs" architecture docs AGENTS.md src
rg -n "config parse fuzz.*not yet implemented|Config parse fuzz target" architecture docs plans/roadmap.md
rg -n "serder.*candidate|legacy_or_stale.*serder|pub mod serder" architecture src
```

Any remaining match must be either:

- intentionally historical and clearly labeled/superseded;
- an accepted residual recorded in `architecture/track3_post_closure_corrective_report.md`;
- or a defect that keeps this corrective pass open.

## Files Expected to Change

Likely:

- `plans/roadmap.md`
- `architecture/ci_fuzz_failure_injection.md`
- `architecture/phase_14_fuzz_execution_report.md`
- `architecture/release_hardening_report.md`
- `architecture/track3_performance_report.md` (only if fuzz evidence is amended there)
- `architecture/track3_post_closure_corrective_report.md` (new)
- `docs/testing/verification-contract.md` only if current wording is inaccurate
- `AGENTS.md` only if current fuzz/verification instructions are inaccurate
- `fuzz/Cargo.toml`
- one new config fuzz target
- `crates/synvoid-config/*` only if a shared pure parse seam is needed
- `src/lib.rs` / `src/serder.rs` if `serder` is removed
- ownership/surface ledgers affected by `serder` disposition

Do not touch unrelated subsystem files.

## Acceptance Criteria

This corrective pass is complete only when all of the following are true:

1. `plans/roadmap.md` has no contradictory Track 3 status/current-state language.
2. Current architecture/operator docs describe the actual single-workflow CI topology and do not advertise removed fuzz/nightly jobs.
3. Historical CI/fuzz reports that retain old topology are clearly marked as historical/superseded where necessary.
4. `http_chunked_framing`, `jail_ipc_frame_decode`, and `http_routing_matcher` each complete the declared 1000-run bounded smoke standard, or an explicit environment blocker remains documented and closure stays open.
5. Any fuzz crash is converted to a deterministic regression test and fixed before closure.
6. `cargo xtask verify-full` passes on the final corrective revision.
7. `cargo xtask verify-release` passes on the final corrective revision.
8. A production-equivalent config parse/validation fuzz target exists and completes 1000 bounded runs, or a precise implementation blocker is documented without claiming the gap closed.
9. `serder` is either removed cleanly or retained with explicit deprecation/replacement/removal policy and a no-new-consumers guard.
10. `architecture/track3_post_closure_corrective_report.md` records exact final evidence and residuals.
11. The canonical routine CI remains one proportional Ubuntu job running `cargo xtask verify`; this pass does not recreate the previously removed verification matrix.
12. No Track 3 architecture contract is weakened to make verification easier.

## Rejection Criteria

Reject the corrective implementation if it:

- creates a new architecture track for bookkeeping-only work;
- restores old CI/nightly workflow complexity solely to make stale documentation true;
- changes the fuzz standard instead of executing or truthfully blocking it;
- records `verify-full`/`verify-release` as passed without executing the canonical commands on the final revision;
- introduces a fuzz-only config parser that does not share production parsing/validation behavior;
- removes `serder` without checking its feature/public-surface implications;
- keeps stale current-state docs because they are inconvenient to reconcile;
- turns historical result documents into misleading rewritten history;
- marks the pass complete with an unexplained failing canonical verification command.

## Handoff Order

Execute serially:

1. Workstream A — establish truthful current-state documentation baseline.
2. Workstream B — normalize Phase 24 fuzz evidence to 1000 runs; fix any crashes immediately.
3. Workstream D — add and smoke-test config parse/validation fuzzing.
4. Workstream E — remove or explicitly deprecate `serder`.
5. Workstream C — run `verify-full` and `verify-release` against the resulting tree.
6. Workstream F — final truthfulness sweep, routine verification, and corrective closure report.

If Workstream B or D discovers a real parser/security bug, fix and regression-test it before proceeding to final verification. Do not broaden this plan unless the discovered defect demonstrates a genuinely new architecture problem.