# Milestone C Phase 5: Validation and Operator Documentation

## Purpose

Close Milestone C with local validation evidence and operator-facing documentation. This phase should not add new functionality except small fixes found during validation. Its output should make the deception pipeline understandable and reproducible for maintainers and operators.

## Preconditions

Milestone C Phases 1-4 should be complete or explicitly marked as partially complete:

- storage writer/backpressure/retention
- threat-intel actionability and mesh propagation policy
- AI responder containment
- tarpit safety/scalability

## Required output files

Create or update:

- `plans/milestone_c_validation_results.md`
- `docs/HONEYPOT.md`
- `docs/TARPIT.md` if absent or stale
- `docs/CONFIGURATION.md`
- `architecture/honeypot.md`
- `architecture/tarpit.md` if present or appropriate
- `SECURITY.md` if operational security posture changed

## Workstream 1: Local validation matrix

Run and record:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
cargo clippy -p synvoid-tarpit --all-targets -- -D warnings
cargo test -p synvoid-tarpit --all-targets
cargo clippy -p synvoid-http --all-targets -- -D warnings
cargo test -p synvoid-http --all-targets
cargo deny check
```

Preferred workspace checks:

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If workspace checks fail outside Milestone C surfaces, classify as unrelated release blocker and create a separate follow-up plan.

## Workstream 2: Storage/operator docs

Document:

- storage writer queue capacity
- batch behavior
- backpressure/drop policy
- payload retention modes
- payload hash/truncation fields
- storage failure metrics
- retention cleanup policy
- SQLite operational limits

Docs must clearly state whether raw payload storage is enabled by default.

## Workstream 3: Threat-intel/actionability docs

Document:

- confidence levels
- severity capping
- action classes
- local rate-limit/block candidate thresholds
- mesh share/block thresholds
- TTL/decay behavior
- dedupe keys
- metadata minimization

Make clear that low-confidence single events are telemetry by default, not block events.

## Workstream 4: AI responder docs

Document:

- responder modes and default mode
- template-only fallback
- local-only/external-provider requirements
- prompt/response/time/concurrency budgets
- error fallback behavior
- what data may be sent to external providers
- why AI output is not an authoritative block signal

If external provider mode remains experimental, label it as such.

## Workstream 5: Tarpit docs

Document:

- escaping rules
- redirect safety policy
- stream admission limits
- duration/byte/chunk budgets
- per-IP/global limits
- fingerprint-resistance behavior
- metrics and logs
- known limitations

## Workstream 6: Metrics and observability map

Create a compact table across honeypot/tarpit:

- metric name
- type
- emitted by
- labels
- operational meaning
- alerting threshold suggestion

Do not invent metrics that were not implemented; mark missing desired metrics as follow-up.

## Workstream 7: Final closure classification

Classify Milestone C:

### Closed

All phases implemented and local validation green.

### Closed with tracked exceptions

Only non-critical docs/workspace/external limitations remain, with follow-up plans.

### Not closed

Any of these remain:

- unbounded storage writer path
- raw payload retention unsafe by default
- low-confidence signal can trigger mesh block
- AI responder enabled externally by default
- AI responder can deadlock/block async runtime
- tarpit open redirect/XSS remains
- tarpit streams are unbounded

## Final acceptance checklist

- [ ] `plans/milestone_c_validation_results.md` exists.
- [ ] Storage writer/backpressure behavior is documented.
- [ ] Payload retention defaults are documented.
- [ ] Threat-intel action classes and mesh thresholds are documented.
- [ ] AI responder mode defaults and budgets are documented.
- [ ] Tarpit escaping and budgets are documented.
- [ ] Local validation commands are recorded.
- [ ] Remaining exceptions have follow-up plans.
- [ ] Final Milestone C status is explicit.

## Handoff guidance

Do not mark Milestone C closed based on implementation commit messages alone. Require the validation results note. If GitHub CI remains unreliable, local validation remains authoritative, but exact command output must be summarized in the repo.
