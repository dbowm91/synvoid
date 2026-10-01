# Phase 104 Plan: Phase 103 Qualification Evidence Corrective Closeout

Status: **ACTIVE / READY FOR IMPLEMENTATION**.

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at
`136bc2143a849b0941b48c80afcb1add2d90a975` (2026-10-01).

Owner: security / release.

Predecessor:

- Phase 103 dependency-security re-audit and Wasmtime remediation,
  implementation SHA `aeeebc7bac38b1dcc441b06f53c838a74582cd24`,
  closeout SHA `136bc2143a849b0941b48c80afcb1add2d90a975`.

## Goal

Correct the two residual qualification defects in the Phase 103 closeout without
reopening the dependency-security remediation itself:

1. replace the non-comparable YARA performance evidence with an actual
   apples-to-apples same-host, same-fixture before/after comparison of the
   Phase 103 Wasmtime 47.0.4 -> 48.0.3 change; and
2. correct the inaccurate Wasmtime 48 LTS support-date statement in the YARA
   compatibility-fork provenance documentation.

No production dependency or runtime change is expected. If the controlled
performance comparison exposes a material regression, this phase stops being a
docs/evidence-only closeout and must open a narrowly scoped runtime corrective.

## Current finding

### 1. Phase 103 performance evidence did not satisfy its own comparison contract

Phase 103 Workstream G required a focused before/after comparison on the same
host and fixtures across the YARA-side Wasmtime major transition.

The landed closeout currently says:

> Focused same-host before/after probe (50 iterations, release profile).

But it records only one Phase 103 data set:

- compile: 1049 us median;
- clean scan: 198 us median;
- matching scan: 183 us median;
- reload: 1121 us median.

It then compares those numbers to Phase 40 measurements that used a different
rule corpus and different payload size, and explicitly states that the result is
not a strict apples-to-apples comparison.

That evidence is useful as a current-state smoke measurement, but it does not
prove the regression condition required by the Phase 103 plan.

### 2. YARA compatibility-fork README carries an incorrect Wasmtime 48 support date

`third-party/yara-x-compat/README.SYNVOID.md` currently says:

`Wasmtime 48.0.3 (48 LTS line, supported for 24 months from 2026-06-04, ...)`

Wasmtime's documented release policy says majors divisible by 12 are LTS
releases supported for 24 months. Wasmtime 48.0.0 was released on
2026-08-20. Therefore the support period for the 48 LTS line is based on the
2026-08-20 release, not 2026-06-04.

The documentation should state either:

- "Wasmtime 48 is an LTS line released 2026-08-20 and supported for 24
  months"; or
- the exact EOL date if independently verified from the upstream support table.

Do not invent an EOL date from arithmetic if upstream publishes an authoritative
one; prefer the upstream support table where available.

## Workstream A — reconstruct an exact pre/post YARA benchmark pair

The benchmark must compare the same code path, fixture, payload, build profile,
host, and measurement method on both sides of the Phase 103 YARA runtime change.

Required comparison points:

- **Before:** Phase 103 planning baseline
  `d960f473aa1ea1b21d2c9e2adc23848addd8de54`, where the YARA fork resolves
  Wasmtime 47.0.4.
- **After:** Phase 103 proof-bearing implementation
  `aeeebc7bac38b1dcc441b06f53c838a74582cd24`, where the YARA fork resolves
  Wasmtime 48.0.3.

Do not compare against Phase 40 benchmark numbers for regression acceptance.

### Benchmark fixture

Use one benchmark source file/script committed temporarily or generated
identically for both checkouts. It must exercise the same four operations on
both SHAs:

1. rule compilation / `reload_with_rules`;
2. clean scan;
3. matching scan;
4. reload/recompile.

The rule corpus and payload bytes must be byte-identical between runs.

Prefer the exact Phase 103 temporary probe shape if it can be reconstructed from
implementation history/tool output. If it cannot be reproduced exactly, define
a new deterministic fixture and run that new fixture on **both** SHAs.

Record:

- source/fixture hash or exact fixture content identity;
- build profile;
- host/CPU/OS;
- iteration count;
- warm-up policy;
- median, min, max for each operation;
- any cache/JIT warm-up behavior that affects interpretation.

At least 50 measured iterations per operation should be retained unless a
stronger repository-standard benchmark protocol already exists.

## Workstream B — calculate and adjudicate the before/after delta

For each of the four operations, calculate:

`delta_pct = (after_median - before_median) / before_median * 100`

Also retain raw medians so the percentage cannot hide small absolute changes.

Classify results conservatively:

- <=5% median change: within ordinary host/noise tolerance unless repeated
  runs show a stable directional regression;
- >5% and <=10%: rerun the affected measurement set to determine whether the
  shift is reproducible;
- >10% repeatable regression: do not close Phase 104 as documentation-only.
  Open a narrow corrective plan to investigate Wasmtime 48/YARA runtime
  behavior before accepting the Phase 103 performance claim.

These thresholds are closeout gates for this corrective only; they do not
establish a general project-wide performance SLO.

Do not tune YARA, Wasmtime, allocator settings, rule structure, or scan
behavior merely to make the numbers pass. The purpose is to measure the landed
security remediation, not optimize it.

## Workstream C — correct the Phase 103 closeout performance section

Update:

`architecture/dependency_security_reaudit_phase103_closeout.md`

Replace the current ambiguous "Focused same-host before/after probe" section
with exact paired data.

The revised section must clearly distinguish:

- the original Phase 103 current-state measurement, if retained;
- the newly reconstructed 47.0.4 baseline;
- the 48.0.3 implementation result;
- percentage delta per operation;
- whether any rerun was required;
- the final regression disposition.

Remove or demote the Phase 40 different-fixture comparison from acceptance
evidence. It may remain as historical context only if explicitly labeled
non-comparable.

The closeout must no longer claim same-fixture before/after evidence unless both
sides are actually recorded.

## Workstream D — correct Wasmtime 48 LTS provenance text

Update:

`third-party/yara-x-compat/README.SYNVOID.md`

Replace the incorrect:

`supported for 24 months from 2026-06-04`

with wording grounded in Wasmtime's documented support policy and release
record.

Minimum acceptable wording:

`Wasmtime 48 is an LTS line released 2026-08-20 and supported for 24 months.`

If the upstream Wasmtime support table exposes the exact EOL date at
implementation time, record that authoritative date as well.

Search the current repository for the erroneous `2026-06-04` date and for
other current-authority statements about Wasmtime 48 support. Correct only
statements that are factually wrong. Do not rewrite historical evidence whose
subject is a different release event.

## Workstream E — preserve Phase 103 security state

This corrective must not change the qualified dependency graph unless the
performance gate forces a separate implementation corrective.

Expected unchanged graph:

- direct Wasmtime: `36.0.16`;
- YARA Wasmtime: `48.0.3`;
- YARA source base: official `yara-x 1.20.0`, manifest-only SynVoid delta;
- `wasmtime-wasi`: absent;
- `wasi-filesystem`: absent;
- no git source;
- no advisory ignore for RUSTSEC-2026-0315 or RUSTSEC-2026-0316;
- retained RSA/rkyv advisory exceptions unchanged from the freshly completed
  2026-10-01 re-audit;
- temporary-fork review deadline remains 2026-11-01.

Any Cargo.toml/Cargo.lock dependency change is unexpected and requires explicit
explanation before closeout.

## Workstream F — verification

Because production code and dependencies are not expected to change, run the
focused integrity/security set after documentation/evidence updates:

```text
cargo test -p synvoid-yara --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo deny check
cargo audit
cargo fmt --all -- --check
cargo xtask verify
```

Also verify:

```text
cargo tree -i wasmtime@36.0.16 --workspace
cargo tree -i wasmtime@48.0.3 --workspace
cargo tree -i wasmtime-wasi --workspace
cargo tree -i wasi-filesystem --workspace
```

Expected:

- exactly the same two Wasmtime ownership paths;
- no WASI filesystem packages;
- advisory policy remains green;
- no lockfile change.

If the benchmark harness is added temporarily, remove it before final commit
unless it is intentionally promoted to a reusable benchmark with separate
justification. The corrective does not require growing the permanent test
surface merely to archive one qualification run.

## Workstream G — corrective closeout and hosted proof

Write:

`architecture/dependency_security_phase104_corrective_closeout.md`

The closeout must record:

- planning baseline;
- benchmark fixture identity;
- before SHA and after SHA;
- host/build/iteration methodology;
- paired raw results and percentage deltas;
- rerun evidence if any operation exceeded the 5% review threshold;
- regression disposition;
- exact documentation correction for Wasmtime 48 LTS support;
- proof that the dependency graph did not change;
- focused verification results;
- proof-bearing corrective SHA;
- hosted CI run ID/link.

After implementation, update:

- this plan to **CLOSED QUALIFIED**;
- `plans/roadmap.md` to Phase 104 **CLOSED QUALIFIED**;
- Phase 103 closeout wording so its performance claim references the Phase 104
  corrective evidence rather than the old non-comparable comparison.

Require hosted CI on the exact proof-bearing Phase 104 SHA:

- `ci`: success;
- `dependency-security`: success.

Because the implementation should be docs/evidence/guard-neutral, native
ICMP/sandbox qualification lanes may remain skipped.

## Acceptance criteria

Phase 104 closes only when all are true:

1. the same deterministic benchmark fixture has been run on
   `d960f473...` and `aeeebc7b...` on the same host;
2. compile, clean-scan, match-scan, and reload medians are recorded for both;
3. percentage deltas are computed and any >5% shift is rerun/adjudicated;
4. no repeatable >10% regression is accepted without a separate corrective
   investigation;
5. the Phase 103 closeout no longer relies on Phase 40 different-fixture data
   as its before/after regression proof;
6. the Wasmtime 48 LTS support statement is corrected to the authoritative
   release/support timeline;
7. no production dependency/runtime change is introduced by this corrective;
8. Wasmtime remains 36.0.16 direct + 48.0.3 YARA transitive, with WASI
   filesystem absent and no git source;
9. `cargo deny check` and `cargo audit` remain green;
10. focused YARA/repo-guard verification and `cargo xtask verify` pass;
11. hosted `ci` and `dependency-security` pass on the exact corrective SHA;
12. a Phase 104 closeout records the corrected evidence.

## Corrective trigger

If the controlled benchmark finds a repeatable >10% regression in one or more
operations:

- leave Phase 104 open;
- do not weaken the acceptance threshold post hoc;
- write a narrow performance/runtime corrective plan;
- investigate whether the delta comes from Wasmtime 48 JIT/codegen,
  compilation configuration, YARA integration behavior, or measurement
  methodology;
- keep the security-remediated 48.0.3 line unless a safe alternative is
  independently justified.

## Non-goals

- No new Wasmtime/YARA version change.
- No YARA-X 1.21 adoption.
- No advisory-policy change.
- No fork-removal decision.
- No plugin-runtime migration.
- No YARA feature/API redesign.
- No Wasmtime tuning campaign.
- No broad benchmark framework addition.
- No reopening of Phase 102 Eggfetch work.
- No unrelated roadmap cleanup.
