# Phase 11 Plan: CI Execution and Release Verification Closure

Status: detailed handoff plan.

Roadmap position: Track 2, Phase 11 of `plans/roadmap.md`.

Primary goal: convert the current “locally verified; CI not observed” status into an externally observable verification story. The repo should either have a visible passing GitHub Actions workflow for the release-required matrix or explicitly document that CI is unavailable and local verification is authoritative.

## Context

The architecture-hardening roadmap is complete on paper and locally verified by committed reports. The remaining trust gap is that GitHub returned no workflow runs and no combined commit statuses for recent commits. Since `.github/workflows/ci.yml` exists, this phase verifies that the workflow actually triggers and that release reports do not imply CI success without evidence.

## Non-Goals

Do not add new architectural features.

Do not weaken tests or guards to make CI pass.

Do not remove expensive jobs without documenting a replacement.

Do not claim CI is green unless a visible workflow run/status proves it.

## Deliverables

1. Verified `.github/workflows/ci.yml` trigger and job matrix.
2. Confirmed executable `scripts/verify_architecture.sh` and alignment with release reports.
3. Visible GitHub Actions run for the latest commit, or explicit documentation that Actions is unavailable.
4. Updated `architecture/final_verification_cleanup_report.md` with CI status.
5. Updated `architecture/release_hardening_report.md`, README, and AGENTS language if CI wording changes.
6. Optional CI badge only after a visible passing run.

## Phase A: Inspect Workflow Trigger and Job Coverage

Inspect:

```bash
sed -n '1,260p' .github/workflows/ci.yml
sed -n '1,220p' scripts/verify_architecture.sh
```

Checklist:

- Workflow has `on: push` and/or `on: pull_request` for `main` or active development branches.
- No path filters exclude documentation/plan commits if the desired behavior is to verify all pushes.
- Jobs include profile checks: default, no-default, mesh, DNS, mesh+DNS.
- Jobs include release-required guard tests.
- Jobs include docs path guard.
- Failure-injection tests run in at least one job.
- Optional fuzz smoke is either present and bounded or documented as manual.
- Rust toolchain setup is explicit and reproducible.
- Cache usage does not hide failures.

If the workflow intentionally does not run on documentation-only changes, create a harmless code/test/CI metadata change to trigger it or document that status cannot be observed from plan-only commits.

## Phase B: Align Script and Release Reports

Compare `scripts/verify_architecture.sh` with:

- `architecture/release_hardening_report.md`
- `architecture/final_verification_cleanup_report.md`
- `AGENTS.md`

The script should include all commands the release report claims as release-required, or the report should state which commands are manual-only.

Required script properties:

- `set -euo pipefail`
- deterministic command order,
- no silent `|| true`,
- clear section headings,
- all release-required guard tests included,
- mesh/DNS feature flags included for relevant guards,
- script file is executable.

Check executable bit:

```bash
git ls-files -s scripts/verify_architecture.sh
```

If not executable, run:

```bash
git update-index --chmod=+x scripts/verify_architecture.sh
```

## Phase C: Run Local Verification Before CI

Run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
./scripts/verify_architecture.sh
```

Then run high-risk tests explicitly if not already included:

```bash
cargo test --test failure_injection
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test security_observability_guard
cargo test --test docs_path_reference_guard
```

Record results in `architecture/phase_11_ci_verification_report.md` or append to `architecture/final_verification_cleanup_report.md`.

## Phase D: Trigger and Observe CI

Preferred path:

1. Commit any workflow/script/report corrections.
2. Push to `main` or open a PR depending on repo practice.
3. Observe GitHub Actions run.
4. Record workflow name, run ID/URL, commit SHA, and status.

If using GitHub CLI:

```bash
gh run list --limit 10
gh run view <run-id> --log-failed
```

If GitHub Actions cannot run:

- Record exact reason: disabled Actions, missing permissions, private repo policy, connector limitation, no trigger, or unknown.
- Keep README/release report wording as “locally verified; CI not observed.”
- Do not add passing CI badge.

## Phase E: Correct CI Failures

If CI fails, fix in this order:

1. Profile compile failures.
2. Guard test failures.
3. Docs path guard failures.
4. Failure-injection flakiness.
5. Environment/toolchain issues.
6. Optional fuzz smoke job.

For flakiness:

- Prefer deterministic tests over retries.
- Add bounded timeouts around async tests.
- Do not globally ignore failures.

## Phase F: Documentation Updates

Update docs based on observed outcome.

If CI passes:

- `architecture/release_hardening_report.md`: add workflow name, run ID/URL, commit SHA.
- `architecture/final_verification_cleanup_report.md`: change “CI not observed” to “CI observed passing” with evidence.
- README: optionally add short status line or badge.

If CI unavailable:

- Keep explicit “local verification only” wording.
- Add a short blocker under release report residual risks.
- Do not add a badge.

## Guardrails to Preserve

Do not remove any of these from CI/script unless there is a documented substitute:

```bash
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test unified_server_lifecycle_ownership_guard
cargo test --test supervisor_task_ownership_guard
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test http3_waf_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test docs_path_reference_guard
cargo test --test failure_injection
cargo test --test security_observability_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

## Acceptance Criteria

This phase is complete when:

- `scripts/verify_architecture.sh` is executable and current.
- CI workflow trigger behavior is verified.
- Release-required profile/guard matrix is either visible in CI or explicitly local-only.
- Release reports and README wording match observed evidence.
- Any CI failures have been corrected or documented as blockers.
- No release artifact claims “CI green” without visible workflow evidence.

## Handoff Notes

This phase is about verification truth, not adding more tests. Add tests only when needed to close a CI coverage gap.

If the connector still reports no workflow runs after a visible web UI run, document the connector limitation separately from CI status.
