# Milestone D Phase 5: Full Workspace Release Validation and Closure

## Purpose

Close Milestone D by rerunning the full workspace validation matrix after tunnel, IPC, ignored-test, and CI parity fixes. This phase must produce a committed release-validation artifact and classify the repository accurately.

The expected output is:

- `plans/milestone_d_validation_results.md`

## Preconditions

Before this phase starts, Phases 1-4 should be complete or explicitly deferred with rationale:

- tunnel/WireGuard feature profile fixed or safely deferred
- IPC clippy warnings fixed
- ignored tests deleted/fixed/quarantined with inventory
- tarpit/mesh/dependency CI parity improved

## Non-goals

- Do not add new product functionality.
- Do not create new milestone scope.
- Do not claim full release-clean if unsupported features still fail without documentation.
- Do not treat missing local tools as pass; record absence explicitly.

## Required validation artifact

Create `plans/milestone_d_validation_results.md` with:

1. Date, branch, commit SHA, Rust toolchain, OS/platform.
2. Exact command matrix and results.
3. Fixes applied during Milestone D.
4. Ignored-test status.
5. CI coverage status.
6. Remaining blockers, if any.
7. Final classification:
   - State A: full workspace release-clean
   - State B: release-clean for supported profiles, tracked exceptions remain
   - State C: release blocked

## Workstream 1: Metadata and formatting

Run:

```bash
rustc --version
cargo --version
rustup show active-toolchain
cargo metadata --no-deps
cargo metadata --all-features --no-deps
cargo fmt --all -- --check
```

Acceptance:

- metadata passes
- formatting passes
- no manifest/license regressions

## Workstream 2: Compile profiles

Run:

```bash
cargo check --workspace
cargo check --workspace --all-targets
cargo check --workspace --all-features
cargo check --workspace --all-targets --all-features
```

Also run known feature profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Tunnel feature profiles:

```bash
cargo check -p synvoid-tunnel
cargo check -p synvoid-tunnel --all-targets
cargo check -p synvoid-tunnel --all-features
```

If WireGuard remains feature-gated:

```bash
cargo check -p synvoid-tunnel --features wireguard
```

Acceptance:

- all supported profiles compile
- unsupported/deferred profiles are documented and not accidentally part of release all-features gate, or are stubbed safely

## Workstream 3: Clippy gates

Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Targeted release-critical crates:

```bash
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo clippy -p synvoid-tarpit --all-targets -- -D warnings
cargo clippy -p synvoid-tunnel --all-targets -- -D warnings
cargo clippy -p synvoid-ipc --all-targets -- -D warnings
cargo clippy -p synvoid-mesh --features mesh --all-targets -- -D warnings
cargo clippy -p synvoid-dns --all-targets -- -D warnings
cargo clippy -p synvoid-waf --all-targets -- -D warnings
```

Acceptance:

- clippy is clean for supported release profiles
- any allow is narrow and justified
- no known Milestone C crates regress

## Workstream 4: Test gates

Run:

```bash
cargo test --workspace
cargo test --workspace --all-targets
cargo test -p synvoid-upload --all-targets
cargo test -p synvoid-honeypot --all-targets
cargo test -p synvoid-tarpit --all-targets
cargo test -p synvoid-tunnel --all-targets
cargo test -p synvoid-ipc --all-targets
cargo test -p synvoid-proxy --all-targets
cargo test -p synvoid-dns --all-targets
cargo test -p synvoid-mesh --features mesh --all-targets
cargo test -p synvoid-waf --all-targets
```

If full workspace tests are too slow, do not silently omit them. Record exact reason and targeted substitutes.

Acceptance:

- workspace tests pass or remaining failures are explicitly non-release-blocking and tracked
- security/deception crates remain green

## Workstream 5: Ignored-test final check

Run:

```bash
rg '#\[ignore\]' . -g '*.rs' -n
cargo test --workspace -- --ignored
```

Acceptance:

- ignored tests are either gone, bounded, or documented
- no ambiguous security-critical ignored tests remain
- bidirectional proxy deadlock tests have a clear status

## Workstream 6: Dependency and security audit

Run:

```bash
cargo deny check
cargo audit
cargo tree -d
cargo tree -i wasmtime
cargo tree -i yara-x
cargo tree -i zip
```

Acceptance:

- cargo-deny passes or has explicit accepted exceptions
- cargo-audit passes or advisories are documented with owner acceptance
- duplicate dependencies are not pathological
- dependency graph for `zip`, `yara-x`, and `wasmtime` is understood

## Workstream 7: CI parity confirmation

Inspect `.github/workflows/ci.yml` and confirm:

- tarpit job exists
- mesh job exists or equivalent mesh profile job exists
- cargo-deny/audit jobs exist
- summary includes all release-critical jobs
- workflow YAML parses

Record whether GitHub Actions results are visible. If not visible, local validation remains authoritative.

## Final classification

### State A: full workspace release-clean

All supported profiles pass metadata, fmt, check, clippy, tests, deny/audit, ignored-test classification, and CI parity.

### State B: release-clean for supported profiles, tracked exceptions remain

Use if:

- supported release profiles are green
- exceptions are unsupported/experimental profiles or explicitly non-release-blocking debt
- exceptions have follow-up plans

### State C: release blocked

Use if:

- workspace supported profiles fail
- security/deception/upload regression appears
- cargo-deny/audit has unaccepted release blocker
- ignored security-critical tests remain ambiguous

## Final acceptance checklist

- [ ] `plans/milestone_d_validation_results.md` exists.
- [ ] Metadata and fmt results recorded.
- [ ] Workspace check results recorded.
- [ ] Workspace clippy results recorded.
- [ ] Workspace test results recorded.
- [ ] Tunnel/WireGuard profile status recorded.
- [ ] IPC clippy status recorded.
- [ ] Ignored-test inventory status recorded.
- [ ] cargo-deny and cargo-audit status recorded.
- [ ] CI tarpit/mesh/audit parity status recorded.
- [ ] Final State A/B/C classification is explicit.

## Handoff notes

This is the milestone closeout phase. If it ends in State B or C, create a precise follow-up plan. Do not leave unresolved failures only in prose or commit messages.
