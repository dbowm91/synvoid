# Milestone D Phase 3: Ignored Test Inventory Cleanup

## Purpose

Resolve the ignored-test debt found in workspace-wide validation. The current inventory is 36 ignored tests: 34 dead overseer-to-supervisor refactor stubs and 2 real bidirectional proxy deadlock tests. This phase should delete, resurrect, or explicitly quarantine each ignored test so release validation is not hiding unknown failures.

## Current issues

From workspace validation:

- 34 ignored tests appear to be dead stubs from the overseer-to-supervisor refactor.
- 2 ignored tests in `crates/synvoid-proxy/src/bidirectional.rs` represent a real bidirectional proxy deadlock issue.
- Ignored tests are not currently classified in a maintained source-of-truth file beyond the validation result note.

## Non-goals

- Do not rewrite the supervisor/overseer architecture.
- Do not silently delete meaningful tests without documenting replacement coverage.
- Do not unignore deadlock tests without bounding their runtime.
- Do not allow security-critical ignored tests to remain ambiguous.

## Workstream 1: Produce exact ignored-test inventory

Run:

```bash
rg '#\[ignore\]' . -g '*.rs' -n
cargo test --workspace -- --ignored
```

Create a table with:

- file path
- test name
- reason for ignore
- category
- action: delete, resurrect, replace, keep ignored with reason
- release-blocking status

Use or update:

- `plans/ignored_tests_inventory.md`

or fold the final table into `plans/milestone_d_validation_results.md` if this phase is combined with final validation.

## Workstream 2: Delete dead overseer/supervisor stubs

For tests classified as dead stubs:

1. Confirm each test references removed architecture, empty scaffolding, or impossible old names.
2. Check whether equivalent supervisor/worker coverage exists.
3. If equivalent coverage exists, delete the dead test.
4. If intent remains valid but coverage is missing, replace with a current supervisor/worker test.

Expected categories:

- empty ignored tests with no assertions
- tests only validating removed `Overseer` names/types
- refactor placeholders with no executable behavior
- integration tests superseded by guard tests

Acceptance:

- no dead ignored stubs remain
- any deleted security-relevant test has replacement coverage or a documented non-release blocker

## Workstream 3: Bidirectional proxy deadlock tests

The two real ignored tests in `crates/synvoid-proxy/src/bidirectional.rs` need deeper handling.

Steps:

1. Open both tests and identify the deadlock condition.
2. Reproduce with a bounded timeout:

```bash
cargo test -p synvoid-proxy bidirectional -- --nocapture
```

3. Add test-level timeouts so future hangs fail deterministically instead of deadlocking the suite.
4. Fix the underlying deadlock if low risk.

Potential fixes to inspect:

- split read/write shutdown ordering
- half-close propagation
- select loop cancellation
- backpressure when one direction closes
- task join ordering
- flush before shutdown
- avoiding awaiting both directions when one can never progress

5. If not fixable in this phase, keep the tests ignored only with:

- explicit reason
- exact bug summary
- owner/follow-up plan
- timeout wrapper if possible

## Workstream 4: Security-critical ignored-test check

Search for ignored tests in security-sensitive areas:

- upload/YARA/archive
- honeypot/tarpit
- DNSSEC/DNS parser
- mesh/block propagation
- plugin runtime guardrails
- WAF attack detection
- proxy tunnel safety

Any security-critical ignored test must be one of:

- unignored and passing
- replaced with current coverage
- documented as release blocker

## Workstream 5: Update CI/test docs

Update:

- `AGENTS.md` ignored-test commands
- `plans/workspace_wide_validation_results.md`, if correcting prior inventory
- `plans/milestone_d_validation_results.md`, if finalizing milestone

## Local validation commands

```bash
cargo fmt --all -- --check
rg '#\[ignore\]' . -g '*.rs' -n
cargo test --workspace -- --ignored
cargo test -p synvoid-proxy --all-targets
cargo test --workspace
```

If deadlock tests are unignored:

```bash
cargo test -p synvoid-proxy bidirectional -- --nocapture
```

Ensure deadlock tests have bounded runtime.

## Success criteria

- 34 dead ignored stubs are deleted or replaced.
- 2 bidirectional proxy deadlock tests are fixed, bounded, or explicitly quarantined with a follow-up plan.
- No ignored upload/honeypot/tarpit/security-critical tests remain ambiguous.
- Ignored-test inventory is accurate and committed.
- Workspace test behavior is more deterministic.

## Handoff notes

Deleting dead tests is acceptable when they no longer test real behavior and current guard/unit tests cover the intent. Keep deletion commits explicit so reviewers can verify that meaningful coverage was not lost.
