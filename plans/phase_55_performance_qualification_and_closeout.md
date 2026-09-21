# Phase 55 Plan: Performance Qualification and Closeout

Status: implementation handoff plan.

Roadmap: `plans/performance_optimization_roadmap.md`.

Depends on: Phases 49-54 complete or explicitly dispositioned.

## Objective

Close the performance campaign with reproducible evidence, full compatibility verification, documentation reconciliation, and explicit disposition of every hypothesis. This phase is not a place to hide late production refactors.

## Workstream A — Re-run the Phase 49 baseline matrix

At the final implementation head, repeat the same-host/profile cases recorded in `architecture/performance_optimization_baseline.md`.

Required comparison table:

- WAF benign path/query/body;
- WAF suspicious/full-detector paths;
- WAF concurrency 1/8/32/128;
- upstream algorithms/pool sizes;
- HTTP buffered-WAF/request ownership path;
- request/global metrics hot paths;
- WASM telemetry hot-key path;
- honeypot enqueue/flush + event-loop lag;
- buffer local/global/growth cases;
- cacheable streaming tee;
- representative end-to-end request workloads.

For each item record:

- baseline;
- final;
- percentage change;
- confidence interval or run variance where available;
- interpretation.

Do not compare incomparable hosts/configurations without clearly labeling the limitation.

## Workstream B — Check semantic parity, not only speed

Create/retain targeted regression tests proving:

- WAF detection/enforcement/scoring parity;
- upstream algorithm/failover parity;
- no request body/header/path mutation from ownership cleanup;
- metrics count each logical event once;
- honeypot retention/hash/order/drain behavior;
- buffer logical bytes are exact after clone/growth/streaming windows;
- cache tee emits exactly the original response body.

Run existing HTTP/TLS/HTTP3/security parity suites that exercise the canonical boundaries changed by this campaign.

## Workstream C — Run supported feature/build matrix

Minimum:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Run `cargo xtask verify-release` on a clean tree when the environment satisfies its prerequisites. It remains qualification-only and must never publish.

If a failure is unrelated environmental evidence, record it precisely; do not mark the command green without execution.

## Workstream D — Produce canonical closeout evidence

Create:

`architecture/performance_optimization_closeout.md`

Required structure:

1. baseline commit and final commit;
2. host/toolchain/configuration;
3. phase status table;
4. benchmark methodology;
5. before/after results;
6. correctness/security parity;
7. memory/RSS results;
8. feature-profile verification;
9. hypothesis disposition table;
10. residual opportunities;
11. rejected changes and why;
12. final compatibility statement.

Classify every original finding as one of:

- measured and implemented;
- measured but not worthwhile;
- not reproduced;
- correctness defect corrected;
- deferred with a concrete reason.

## Workstream E — Reconcile performance documentation

Update current-state docs only where the final implementation changes their claims.

Audit at least:

- `docs/PERFORMANCE.md`;
- `architecture/waf.md`;
- `architecture/networking_deep_dive.md`;
- `architecture/track3_performance_report.md` (historical—link forward rather than rewriting old evidence);
- `architecture/overview.md`;
- `AGENTS.md` if implementation guidance changed;
- relevant `.opencode/skills/*/SKILL.md` files, especially streaming WAF guidance.

Historical Track 3 and Phase 41-48 reports remain historical. Do not rewrite old benchmark numbers into the new campaign.

## Workstream F — Close planning status

After all acceptance criteria are satisfied:

- mark `plans/performance_optimization_roadmap.md` complete/historical;
- mark Phases 49-55 implemented/closed while preserving original intent;
- update `plans/roadmap.md` so no active handoff remains for a completed campaign;
- point plan statuses at `architecture/performance_optimization_closeout.md`.

If any phase is incomplete, the umbrella roadmap must remain active and name the exact residual. Do not close by prose alone.

## Performance acceptance policy

A change is a successful optimization when the relevant representative workload improves and no material regression appears elsewhere.

Default interpretation:

- >5% regression in a primary hot-path benchmark or end-to-end tail metric is material until explained;
- a statistically clear improvement in a high-frequency operation can justify smaller percentage gains;
- a microbenchmark gain can be rejected if p99, event-loop lag, RSS, code complexity, or maintenance burden worsens;
- correctness/security parity overrides performance.

Do not aggregate unrelated benchmark percentages into one synthetic score.

## Acceptance criteria

Phase 55 and the campaign are complete only when:

- all Phase 49 baseline cases have final comparable evidence or a documented reason they cannot be reproduced;
- public API/config/protocol/metric capability remains intact;
- WAF/security parity suites are green;
- all supported feature profiles compile;
- `cargo xtask verify` and `cargo xtask verify-full` are green at the closeout head;
- dependency-security results are recorded;
- `architecture/performance_optimization_closeout.md` exists;
- performance/current-state documentation matches landed behavior;
- each original hypothesis has an explicit final disposition;
- planning status is reconciled only after evidence is complete.

## Rejection criteria

Reject closeout that:

- reports only the best microbenchmarks;
- omits regressions in p99/event-loop lag/RSS;
- claims an optimization that actually removes work/capability;
- ignores failed security or feature-profile tests;
- rewrites historical performance records instead of adding a new dated record;
- marks plans complete while implementation/evidence is still missing.
