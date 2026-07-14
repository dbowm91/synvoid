# Testing Infrastructure Milestone D — Final Closure Plan

## Purpose

Milestone D’s affected-package selection and workflow gating are now structurally correct, fail closed, and protected by regression tests. The remaining work is a narrow closure pass before Milestone E begins:

1. correct the apparent non-Linux compile failure introduced in the DNS fallback TCP packet-info tests;
2. reconcile the documented compiler-cache design with the current reality that `sccache` was removed from the PR fast lane;
3. verify cross-platform workflow behavior on hosted runners;
4. verify branch-protection authority and stable required checks;
5. update result documents so they describe the final implementation rather than the pre-rollback state.

This plan must not expand into Milestone E fixture, concurrency, fuzz, stress, or testkit work. It closes correctness and operational-authority gaps in the existing Milestone D implementation.

## Current state

The repository currently has:

- correct affected-job predicates using `mode == 'full' || package-selected`;
- fail-closed selector normalization to full validation;
- selector workflow regression guards and Python tests;
- a shared Rust CI setup action used by the principal compilation-heavy PR jobs;
- release-qualification matrix deduplication;
- affected-package local reproduction tooling;
- `sccache` support in the shared action and cache-policy documentation, but no active `sccache` use in the PR workflow after the GitHub Actions cache backend failed;
- a stale `SCCACHE_GHA_ENABLED` environment declaration in `pr-fast.yml`;
- fallback DNS tests that construct a `std::net::TcpStream` using a nonexistent `bind` associated function under `#[cfg(not(target_os = "linux"))]`;
- no authoritative hosted-runner timing or branch-protection evidence available in the committed result documents.

## Scope

In scope:

- non-Linux DNS fallback test correction;
- Linux, macOS, Windows, and FreeBSD compile/test validation for the touched platform module;
- cache-policy reconciliation and removal of stale configuration;
- explicit `sccache` disposition;
- hosted-runner validation of selector skipping and fail-closed fallback;
- branch-protection required-check audit;
- final Milestone D closure results.

Out of scope:

- new cache services or self-hosted infrastructure unless separately approved;
- broad DNS architecture changes;
- fixture deduplication;
- test parallelism changes;
- fuzz, stress, endurance, or benchmark restructuring;
- developer test CLI work beyond correcting existing documentation.

## Workstream D-C1 — Correct non-Linux TCP fallback test construction

### Problem

The fallback tests currently attempt:

```rust
std::net::TcpStream::bind("127.0.0.1:0")
```

`TcpStream` has no `bind` constructor. These tests compile only on non-Linux targets and therefore may evade the Linux PR lane.

### Required implementation

Use a real loopback TCP pair through a helper local to the test module:

```rust
fn loopback_tcp_stream() -> std::net::TcpStream {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener address");
    let accept = thread::spawn(move || listener.accept().map(|(stream, _)| stream));
    let client = TcpStream::connect(addr).expect("connect loopback stream");
    let _server = accept.join().expect("accept thread").expect("accept stream");
    client
}
```

The implementation may instead use a smaller platform-test helper if it guarantees:

- no external network dependency;
- no fixed port;
- deterministic cleanup;
- a valid `TcpStream` reference;
- compatibility with macOS, Windows, and FreeBSD.

Do not weaken the trait merely to make the fallback test easier unless production callers demonstrate that a stream reference is architecturally unnecessary.

### Required tests

- fallback implementation returns an error;
- error mentions `IP_PKTINFO` or the documented capability name;
- fallback reports `supports_tcp_pktinfo() == false`;
- test helper does not leak listener threads or sockets;
- Linux implementation tests remain unchanged and pass.

### Validation

```bash
cargo fmt --all -- --check
cargo test -p synvoid-dns --profile ci platform
cargo check -p synvoid-dns --target x86_64-apple-darwin
cargo check -p synvoid-dns --target x86_64-pc-windows-msvc
```

Where local target toolchains cannot link, at minimum run `cargo check` with the target installed and rely on hosted native jobs for execution.

### Exit criteria

- no use of `TcpStream::bind` remains;
- the fallback test module compiles on all supported non-Linux targets;
- native macOS or Windows CI exercises the fallback tests;
- the Linux packet-info path remains green.

## Workstream D-C2 — Add a cross-platform regression guard

Add a lightweight source or compile guard preventing recurrence of invalid platform-only test construction.

Preferred options, in priority order:

1. a native cross-platform test job that compiles and runs `synvoid-dns` tests;
2. target-specific `cargo check --tests` matrix entries;
3. a static guard rejecting known invalid constructors only as a supplementary defense.

The authoritative protection should be compilation, not token scanning.

Add a targeted workflow entry or ensure an existing nightly/main job runs:

```bash
cargo test -p synvoid-dns --profile ci
```

on macOS and Windows. FreeBSD remains qualification-lane coverage.

### Exit criteria

- non-Linux platform code cannot merge without at least compilation coverage;
- platform-only test code is included in the target matrix;
- the coverage rationale is documented in `docs/testing/feature-target-matrix.md`.

## Workstream D-C3 — Reconcile `sccache` design with current operation

### Required decision

Choose and document one of two dispositions.

#### Disposition A — Formally defer `sccache`

Use this unless a supported cache backend is verified immediately.

- Remove `SCCACHE_GHA_ENABLED` from workflows where `sccache` is not enabled.
- Keep optional `sccache` support in the shared action only if it is tested and clearly marked dormant/experimental.
- Update `docs/testing/cache-policy.md` to state that compiler-object caching is deferred because the selected GitHub Actions backend was unavailable in the current runner context.
- Update Milestone D result documents so they do not claim active `sccache` deployment or measurable hit rates.
- Retain `Swatinem/rust-cache` as the active cache mechanism.
- Create an explicit future trigger for reevaluation, such as runner/backend availability or self-hosted CI adoption.

#### Disposition B — Restore `sccache` with a proven backend

Only choose this after proving the backend works on the actual repository runners.

- configure the supported backend;
- verify credentials and cache endpoint availability;
- run cold and warm comparisons;
- report hit rate, cache write/read latency, and net workflow time;
- fail open to normal Rust compilation if cache service initialization fails;
- ensure no secret or cross-fork exposure.

Do not re-enable `sccache` merely because installation succeeds. The backend must store and retrieve artifacts successfully.

### Required documentation corrections

Audit and reconcile:

- `.github/workflows/pr-fast.yml`;
- `.github/actions/setup-rust-ci/action.yml`;
- `docs/testing/cache-policy.md`;
- `plans/testing_milestone_d_results.md`;
- `plans/testing_milestone_d_corrective_closure_results.md`;
- `AGENTS.md` and README testing commands.

### Exit criteria

- no stale environment variables imply an inactive cache is enabled;
- documentation states the actual active cache layers;
- optional dormant capability is labeled accurately;
- no CI job fails because a cache backend is unavailable.

## Workstream D-C4 — Hosted-runner selector validation

Run representative PR scenarios through GitHub-hosted runners.

Required scenarios:

1. documentation-only change;
2. localized `synvoid-upload` change;
3. localized `synvoid-mesh` change;
4. workspace `Cargo.toml` change;
5. `Cargo.lock` change;
6. selector-script change;
7. workflow-file change;
8. intentionally invalid base or selector failure through a controlled test branch;
9. manual `force-full` dispatch.

For each scenario, record:

- selector mode;
- selected packages;
- selected root tests;
- package jobs run;
- package jobs skipped;
- summary result;
- fallback annotations;
- elapsed workflow time;
- cache restore/save time where available.

### Required invariants

- documentation-only changes do not run unrelated package jobs unless a conservative fallback rule intentionally requires full validation;
- localized package changes select reverse dependents correctly;
- workspace/dependency/workflow changes force full mode;
- selector failures force full mode;
- the aggregate summary succeeds when optional jobs are skipped;
- required always-on checks keep stable check names.

### Exit criteria

- at least one real affected-mode PR demonstrates package skipping;
- at least one full-mode PR demonstrates all package jobs running;
- at least one failure-path test demonstrates fail-closed normalization;
- results are recorded in the closure report.

## Workstream D-C5 — Branch-protection authority audit

A repository administrator must verify the actual branch-protection configuration.

Required checks should be based on stable, always-present jobs. Recommended required set:

- `PR Fast / Rustfmt`;
- `PR Fast / Clippy (default features)`;
- `PR Fast / No Unsafe in DNS`;
- `PR Fast / Core Profile (No Default Features)`;
- `PR Fast / Forbidden Import Patterns`;
- `PR Fast / Security Regression Tests`;
- `PR Fast / Architecture Guard Tests`;
- `PR Fast / PR Fast Summary`.

Selector-gated package jobs should not individually be required if GitHub treats skipped required checks as blocking in the repository’s protection configuration. The always-running summary should aggregate their status.

Verify:

- no legacy `ci.yml` job names remain required;
- no optional gated job can block because it was intentionally skipped;
- the summary fails when a required or selected job fails;
- the summary accepts intentional skips;
- force-full mode remains available for reviewers or administrators.

### Exit criteria

- branch protection is verified against live repository settings;
- exact required check names are documented;
- a test PR proves mergeability with intentional skips;
- a test PR proves failures block merging.

## Workstream D-C6 — Final validation matrix

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo check --workspace --profile ci
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
python3 -m pytest tests/ci/test_select_affected.py
python3 scripts/ci/select-affected.py --base HEAD~1 --head HEAD --format json
bash scripts/test-affected.sh HEAD~1 --dry-run
```

Platform validation:

```bash
cargo test -p synvoid-dns --profile ci
cargo check -p synvoid-dns --tests --target x86_64-apple-darwin
cargo check -p synvoid-dns --tests --target x86_64-pc-windows-msvc
```

Run native hosted jobs where cross-target dependencies cannot be checked from Linux.

### Exit criteria

- local validation passes;
- native non-Linux validation passes;
- selector tests and guards pass;
- current cache configuration does not emit backend failures;
- branch-protection behavior is proven.

## Workstream D-C7 — Closure documentation

Create:

```text
plans/testing_milestone_d_final_closure_results.md
```

Record:

- exact commits;
- DNS fallback test fix;
- platform matrix results;
- selected cache disposition;
- active cache layers;
- hosted selector scenarios;
- branch-protection check names;
- cold/warm timing data available from current cache layers;
- unresolved external constraints;
- go/no-go recommendation for Milestone E.

Update all stale Milestone D documentation.

## Recommended commit sequence

1. Fix non-Linux DNS fallback test construction and add tests.
2. Add or correct non-Linux DNS test coverage in CI.
3. Reconcile cache workflow configuration and documentation.
4. Run hosted selector scenarios and branch-protection audit.
5. Commit closure results and final documentation corrections.

Keep source correctness fixes separate from CI/cache policy changes.

## Rollback strategy

- If the DNS helper is flaky, replace it with a synchronous loopback pair helper using deterministic thread joining; do not skip the test.
- If affected selection behaves incorrectly on hosted runners, force `mode=full` globally while preserving selector diagnostics.
- If branch protection cannot handle skipped jobs reliably, require only always-running checks plus the aggregate summary.
- If a cache backend remains unavailable, formally defer compiler-object caching and retain rust-cache only.

## Final exit criteria

Milestone D is closed only when:

- non-Linux DNS fallback tests compile and pass;
- native non-Linux validation exists;
- affected job skipping is demonstrated on a real PR;
- selector failures demonstrably fall back to full mode;
- branch protection points to stable current checks;
- cache documentation matches active configuration;
- no stale `sccache` environment or claims remain;
- a final closure report records evidence;
- no unresolved Milestone D issue affects the validity of Milestone E measurements.
