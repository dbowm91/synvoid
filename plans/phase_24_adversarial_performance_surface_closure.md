# Phase 24 Plan: Adversarial Verification, Performance Baselines, and Surface Closure

Status: complete (2026-09-09). Closure evidence: `architecture/track3_performance_report.md`, `architecture/crate_granularity_audit.md`, `tests/track3_invariant_closure.rs`, `tests/http_differential_closure.rs`, `tests/track3_concurrency_closure.rs`, 3 new fuzz targets (`http_chunked_framing`, `jail_ipc_frame_decode`, `http_routing_matcher`), 5 new benchmark groups, reconciled ledgers (`root_module_ledger.md`, `root_module_burndown_report.md`, `final_surface_audit.md`, `release_hardening_report.md` amendment), routine CI extended by 7 fast suites with no new jobs.

Roadmap position: Track 3, Phase 24 of `plans/roadmap.md`.

Primary goal: close Track 3 with focused hostile-input, state-machine, concurrency, and hot-path performance evidence, then use that evidence to retire stale compatibility surfaces and reassess crate granularity without expanding CI back into a large verification apparatus.

## Context

Track 2 established CI/fuzz smoke infrastructure and existing benchmark coverage is already broad. The current repository contains Criterion benches for areas such as normalization, attack detection, rate limiting, proxy headers/cache, WASM, DNS, and broadcast behavior. This phase therefore must not create a second benchmark framework or duplicate Phase 14's generic fuzz setup.

The gaps relevant to the Track 3 refactors are narrower:

- security-critical HTTP framing/normalization should be hostile-input tested against the newly canonical path;
- enforcement reducer/action mappings need property-style invariants;
- jail IPC needs malformed-frame/process-failure testing;
- distributed state needs deterministic partition/replay/expiry state-machine tests;
- high-contention state such as rate limiting/block storage deserves targeted concurrency verification;
- hot-path refactors need before/after baselines;
- stale benchmark/compatibility/module surfaces should be removed after ownership converges.

## Constraints

- Reuse the existing CI, fuzz, Criterion, and verification-script infrastructure.
- Do not add a broad new workflow matrix or permanent benchmark CI gate unless current runtime/noise makes it clearly practical.
- Prefer regression tests produced from fuzz crashes over relying only on ongoing fuzz execution.
- Benchmarks should detect material regressions, not enforce unstable nanosecond thresholds across heterogeneous CI hosts.
- Do not retain compatibility surfaces solely because deleting them would make the audit less convenient; apply the repository's stability policy.

## Part A: Track 3 invariant test suite

Add focused tests for the architectural contracts created in Phases 17–23.

### Enforcement contract

Verify:

- reducer pairwise precedence
- order independence
- idempotence
- exhaustive adapter mappings
- source/reason preservation
- allow/observe cannot weaken terminal actions

### Ownership/facade guards

Verify:

- domain crates cannot import root compatibility paths
- root facade-classified modules remain thin
- no duplicate HTTP normalization helper is added under root
- no duplicate WAF terminal-action enum appears without registration
- removed no-op compatibility methods gain no new callers

### Jail process

Verify protocol and process failure semantics from Phase 22, including malformed frames, timeout, crash, parent EOF, restart bounds, and required-isolation fail-closed behavior.

### Distributed state

Verify partition/rejoin, stale/replay/expiry, quorum-unavailable, and advisory policy-gate invariants from Phase 23.

## Part B: Expand fuzzing only at uncovered high-risk boundaries

Review `architecture/ci_fuzz_failure_injection.md`, current `fuzz/fuzz_targets/`, and the Track 2 execution report before adding targets.

Add or complete targets only where the current inventory does not already provide equivalent coverage.

Highest-value candidates from the current audit are:

- HTTP/1 chunked-body/framing parser
- request-target/path normalization and routing matcher
- config parse/validation if still listed as missing
- canonical enforcement adapter/reducer serialized inputs if externally deserialized
- jail IPC frame decoder
- mesh/canonical/distributed-state message decoders newly introduced or materially changed in Phase 23

Each fuzz target must:

- have strict input/resource bounds
- avoid external network access
- avoid persistent filesystem mutation outside temp fixtures
- complete a bounded smoke run
- convert any discovered deterministic crash into a normal regression test

Do not add fuzz targets for pure internal constructors with no hostile/external input surface.

## Part C: HTTP differential/property tests

For normalization-sensitive cases, add a corpus of equivalent and adversarial requests and prove that:

- canonical parse + normalization is deterministic
- routing and WAF consume the same security-relevant normalized target
- HTTP/1 and HTTP/3 representations yield equivalent policy where their semantics overlap
- percent-encoding/dot-segment variants cannot bypass path rules
- forwarding headers cannot override direct client identity unless the direct peer is trusted
- body/framing rejection is deterministic and fail closed

Use table/property tests rather than maintaining duplicate expected parsers.

## Part D: Targeted concurrency verification

Audit the highest-contention state touched by recent correctness fixes and Track 3 changes, especially:

- rate limiter acquire/release/bucket lifecycle
- block-store concurrent read/update/remove paths
- challenge-attempt accounting if moved in Phase 18
- jail request queue/process restart state
- distributed cursor/state application

Use the lightest effective technique:

1. deterministic unit/state-machine tests where possible;
2. high-iteration multithreaded stress tests for atomic/map invariants;
3. Loom only for small synchronization components whose abstraction can realistically be modeled.

Do not force Loom across large Tokio/network stacks.

Required invariants include:

- counters never underflow/overflow silently
- release does not remove a concurrently reacquired entry
- no stale state resurrects after remove/unblock
- bounded maps/queues enforce bounds under concurrency
- restart/drain races do not leak child processes/tasks

## Part E: Hot-path benchmark consolidation

Inventory existing benchmarks and map them to Track 3 hot paths.

At minimum retain or add representative baselines for:

- benign request parse/normalization
- encoded/adversarial normalization
- WAF allow/no-match path
- WAF terminal decision/reducer overhead
- rate-limit lookup/update
- block-store lookup/admission
- proxy/forward-header construction
- streaming/body-policy common path
- jail IPC round-trip separately from WASM execution cost

Prefer extending existing Criterion benches such as normalization, attack detection, ratelimit, proxy headers, and WASM rather than adding many new binaries.

Record a small baseline report in `architecture/track3_performance_report.md` containing environment, command, representative median/throughput data, and before/after comparison where a meaningful pre-refactor revision is available.

Do not claim absolute 1M RPS from microbenchmarks. Use them as regression indicators only.

## Part F: Remove stale benchmark/test artifacts

Audit benches/tests for disabled or stale cases. The current tree contains at least one benchmark with a TODO for a removed attack-detection method. Remove dead benchmark functions/files or update them to current APIs.

Apply the same rule to:

- tests of removed compatibility shims
- architecture guards referencing obsolete file paths
- old evidence files that incorrectly describe current active behavior

Do not delete historical plan/result documents that are intentionally archival; update their status or link to newer canonical reports instead.

## Part G: Crate granularity audit

After ownership convergence, reassess workspace crate boundaries from the actual final dependency graph.

Create `architecture/crate_granularity_audit.md` with one row per workspace crate:

| Crate | Responsibility | Independent invariants? | External/reuse value? | Root dependents | Internal deps | Keep/Merge candidate | Rationale |
|-------|----------------|-------------------------|-----------------------|-----------------|---------------|----------------------|-----------|

Retain a crate when it provides meaningful one or more of:

- independently testable invariants/security boundary
- reusable/public API
- dependency isolation
- feature/build isolation
- compile-time ownership boundary

Flag a merge candidate when it is primarily a naming/module wrapper with no independent invariants and meaningful cross-crate churn/boilerplate.

Do not execute a broad merge sweep in this phase. Only perform obvious low-risk collapses when:

- public stability policy permits it
- there are no downstream consumers or compatibility costs are trivial
- dependency direction improves
- tests are straightforward

Otherwise record candidates for a future intentionally scoped simplification pass.

## Part H: Root/public surface closeout

Re-run the root module and public surface audits after all Track 3 phases.

Required updates:

- `architecture/root_module_ledger.md`
- `architecture/root_module_burndown_report.md`
- `architecture/root_dependency_ownership.md`
- `architecture/final_surface_audit.md`
- `architecture/release_hardening_report.md`
- `architecture/semver_stability_policy.md` where classifications changed
- `scripts/verify_architecture.sh` guard inventory if tests changed

The ledger, burn-down report, and final surface audit must agree on every remaining `split_required`, `keep_app_root`, facade, and stale module.

Any remaining `split_required` module must have a precise blocker and a named follow-up plan; otherwise Track 3 is not closed.

## Part I: CI integration policy

Keep routine CI bounded.

Suitable routine checks:

- formatting/check/clippy already present
- focused architecture guard suite
- ordinary regression tests
- short fuzz smoke if already supported and stable

Prefer manual/nightly/local for:

- long fuzz campaigns
- large Criterion benchmark suites
- expensive partition/stress iterations
- platform-specific sandbox drills

Document exact release-candidate commands rather than adding many always-on jobs.

## Acceptance criteria

Phase 24 is complete when:

- every Track 3 architectural invariant has focused automated coverage
- newly canonical HTTP/jail/distributed parsers have hostile-input fuzz or equivalent robust parser tests where appropriate
- deterministic fuzz failures are captured as regression tests
- targeted concurrency invariants pass under repeated stress/model tests
- hot-path benchmarks cover request normalization, WAF allow/decision, rate/block lookup, and jail IPC overhead
- a compact Track 3 performance report records relevant before/after evidence without overstated throughput claims
- stale/dead benchmark/test artifacts are removed or corrected
- crate granularity audit exists and distinguishes real isolation boundaries from thin organizational crates
- root module ledger, burn-down report, dependency ownership, and final surface audit agree
- no remaining `split_required` module lacks a precise blocker/follow-up
- CI complexity is not materially expanded to support this closure

## Rejection criteria

Reject an implementation that:

- creates another benchmark/fuzz framework instead of using existing infrastructure
- gates normal CI on unstable machine-specific microbenchmark thresholds
- treats code coverage percentage as a substitute for parser/state-machine adversarial tests
- creates broad Loom models for entire async/network stacks
- merges crates solely to reduce crate count
- deletes compatibility/public surfaces without applying stability policy
- declares Track 3 closed while architecture ledgers disagree

## Verification

Final Track 3 verification should include:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
./scripts/verify_architecture.sh
```

Run bounded smoke fuzzing for the selected targets, targeted concurrency/stress tests, the relevant Criterion benches, the sandbox runtime drill, and mesh partition/rejoin tests. Record only compact reproducible evidence in the architecture reports.
