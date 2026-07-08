# Milestone D Phase 4: CI Coverage Parity for Tarpit, Mesh, Audit, and Workspace Gates

## Purpose

Bring CI closer to the local validation matrix. Current local validation is authoritative, but the workflow should still exercise the important release gates so future regressions are visible. This phase adds missing tarpit and mesh coverage, verifies cargo-deny/audit coverage, and aligns CI summary output with actual jobs.

## Current issues

From workspace validation:

- No dedicated CI job for `synvoid-tarpit` tests.
- No dedicated mesh integration test job.
- Existing CI has many jobs but must be checked for summary drift.
- Local `cargo-deny` and `cargo-audit` were unavailable in one validation pass, so CI coverage matters for dependency/security gates.

## Non-goals

- Do not make CI the only source of truth for Milestone D closure.
- Do not add expensive exhaustive jobs that make CI unusable.
- Do not duplicate every local command in CI if a targeted matrix is sufficient.
- Do not hide flaky jobs behind `continue-on-error` unless explicitly experimental and non-release-blocking.

## Workstream 1: Inspect existing workflow

Open `.github/workflows/ci.yml` and inventory:

- build job
- fmt job
- clippy job
- upload job
- honeypot job
- DNS jobs
- security/audit jobs
- dependency audit / cargo-deny jobs
- profile matrix
- guard suites
- summary job

Confirm:

- every referenced `needs` job exists
- summary prints every release-critical job
- deleted job names are not referenced
- new tarpit/mesh jobs are added to summary

## Workstream 2: Add tarpit CI job

Add a dedicated tarpit job:

```yaml
tarpit-tests:
  name: Tarpit Crate Tests
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with:
        components: clippy, rustfmt
    - uses: Swatinem/rust-cache@v2
    - run: cargo fmt -p synvoid-tarpit -- --check
    - run: cargo clippy -p synvoid-tarpit --all-targets -- -D warnings
    - run: cargo test -p synvoid-tarpit --all-targets
```

If `cargo fmt -p` is unsupported in the repo/toolchain, use workspace fmt in the existing fmt job and omit per-package fmt here.

## Workstream 3: Add dedicated mesh validation job

Add a mesh job that is meaningful but bounded:

```yaml
mesh-tests:
  name: Mesh Crate Tests
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with:
        components: clippy, rustfmt
    - uses: Swatinem/rust-cache@v2
    - run: cargo check -p synvoid-mesh --features mesh --all-targets
    - run: cargo clippy -p synvoid-mesh --features mesh --all-targets -- -D warnings
    - run: cargo test -p synvoid-mesh --features mesh --all-targets
```

If mesh tests require external network or deterministic timing, split:

- unit/compile job in required CI
- external integration job as manual/nightly

Do not pretend manual/nightly coverage is required release coverage.

## Workstream 4: Dependency/security jobs

Confirm or add jobs for:

```bash
cargo deny check
cargo audit
```

If both exist, ensure versions are pinned or installed reliably.

If `cargo audit` duplicates deny advisory checks but still desired, document why both run.

If cargo-deny advisories are intentionally ignored, CI must fail on new advisories except explicitly ignored dated entries.

## Workstream 5: Workspace gate job

Add or confirm a bounded workspace gate:

```bash
cargo check --workspace --all-targets
cargo test --workspace --no-fail-fast
```

If full workspace test is too slow, use a release-critical matrix:

- upload
- honeypot
- tarpit
- http
- waf
- dns
- mesh
- proxy
- plugin-runtime

Document why full workspace is not used.

## Workstream 6: Summary job and docs

Update summary job:

- include tarpit-tests
- include mesh-tests
- include cargo-deny/audit jobs
- include workspace gate if added

Update docs:

- `AGENTS.md` CI section
- `plans/milestone_d_validation_results.md` after final pass

## Local validation commands

Before committing CI changes, run syntax/basic checks:

```bash
python - <<'PY'
import yaml
from pathlib import Path
p = Path('.github/workflows/ci.yml')
yaml.safe_load(p.read_text())
print('workflow yaml parses')
PY
```

If PyYAML is unavailable:

```bash
ruby -e "require 'yaml'; YAML.load_file('.github/workflows/ci.yml'); puts 'workflow yaml parses'"
```

Also run the commands introduced in CI locally where feasible:

```bash
cargo clippy -p synvoid-tarpit --all-targets -- -D warnings
cargo test -p synvoid-tarpit --all-targets
cargo check -p synvoid-mesh --features mesh --all-targets
cargo test -p synvoid-mesh --features mesh --all-targets
cargo deny check
cargo audit
```

## Success criteria

- CI has dedicated tarpit coverage.
- CI has dedicated mesh coverage or a clearly documented bounded substitute.
- cargo-deny and cargo-audit coverage is present or explicitly justified.
- CI summary references all required jobs and no stale jobs.
- Workflow YAML parses.
- Local commands corresponding to new jobs pass or failures are documented.

## Handoff notes

Because CI visibility has been unreliable in prior work, do not use workflow changes alone to claim release readiness. Pair this phase with Phase 5 local validation results.
