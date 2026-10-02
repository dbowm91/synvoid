# Phase 113 Plan: Subsystem Boundary Closeout Evidence Reconciliation

Status: **ACTIVE / READY** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline: `main` at
`4d957b2e90c29c018430bdac8af830b9db91b19a` (2026-10-02).

Owner: architecture / release documentation.

Predecessor: Phase 112 CLOSED QUALIFIED.

## Goal

Repair current-authority documentation drift left after the Phase 105–112
campaign closeout without changing production code, dependency resolution,
support claims, or the substantive domain dispositions.

The campaign's qualified implementation evidence remains valid:

- proof-bearing implementation SHA
  `e7c0ec5a1317599b6f98e37a534b53544842a29c`;
- hosted exact-SHA run `36955732943` passed `ci` and
  `dependency-security`;
- `cargo xtask verify` passed all 10 steps;
- `cargo xtask verify-full` passed all 10 steps;
- `cargo xtask verify-release` passed 14/14 steps;
- final `cargo deny check` passed;
- final `cargo audit` reported no vulnerabilities and the six already
  accepted unmaintained warnings.

This phase exists because several current-authority sections still describe
those same checks or phase states as pending/planned.

## Current defects

### 1. Terminal closeout contains a stale pending-verification block

`architecture/subsystem_boundary_extraction_closeout.md` correctly records the
passing final evidence near the top, but its later
`## Verification and residuals` section still says:

- final-head verification is pending;
- `cargo fmt` is Pending;
- `cargo xtask verify` is Pending;
- `cargo xtask verify-full` is Pending;
- `cargo xtask verify-release` is Pending;
- final dependency-security repeat is pending;
- hosted exact-SHA proof is Pending.

Those statements contradict the same file's terminal proof record and the
global roadmap.

### 2. Global roadmap retains stale campaign state in its detailed section

The top-level `plans/roadmap.md` status correctly says Phases 105–112 are
CLOSED QUALIFIED, but the detailed section heading still says:

`Post-Phase-104 Campaign: Subsystem Boundary and Extraction — Phases 105–112 ACTIVE / REGISTERED`

and its embedded Phase 108 entry still says:

`PLANNED / READY`

despite Phase 108 being CLOSED QUALIFIED.

### 3. Umbrella/current-authority references must agree

`plans/subsystem_boundary_extraction_roadmap.md`, the global roadmap, Phase
112, and the architecture closeout must all agree on:

- campaign terminal status;
- Phase 105–112 terminal dispositions;
- proof-bearing SHA;
- hosted run ID;
- no downstream extraction plan unblocked by Phase 112.

Historical plan text may preserve original execution instructions where clearly
historical, but no current-status sentence may contradict terminal authority.

## Scope

Documentation/evidence reconciliation only.

Authorized files are limited to current authority and immediately related plan
status text, primarily:

- `architecture/subsystem_boundary_extraction_closeout.md`;
- `plans/roadmap.md`;
- `plans/subsystem_boundary_extraction_roadmap.md`;
- `plans/phase_112_extraction_gate_refresh_campaign_closeout.md` if needed;
- individual Phase 105–111 plan headers/status summaries only when a current
  status statement is objectively stale.

No Rust source, Cargo manifest, lockfile, workflow, dependency version, or
runtime behavior change is authorized.

## Workstream A — replace stale pending verification with terminal evidence

Rewrite the stale `Verification and residuals` block in the campaign closeout
to report the already-established terminal results.

The corrected section must include at least:

| Verification | Terminal evidence |
| --- | --- |
| `cargo fmt --all -- --check` | Passed on proof-bearing tree |
| `cargo xtask verify` | 10/10 passed |
| `cargo xtask verify-full` | 10/10 passed; 7,896 tests across 217 binaries, 8 skipped |
| `cargo xtask verify-release` | 14/14 passed |
| `cargo deny check` | Passed |
| `cargo audit` | No vulnerabilities; six accepted unmaintained warnings |
| hosted `ci` + `dependency-security` | Run `36955732943` passed on `e7c0ec5...` |

Do not invent native ICMP/sandbox evidence: those hosted jobs were skipped by
workflow conditions and Phase 112 made no new native qualification claim.

Preserve the legitimate accepted residuals:

- honeypot and DNS remain in-workspace;
- native evidence remains platform-scoped;
- tunnel parity/adoption remained deferred by Phase 111;
- independent package support gates remain open.

Phase 114 separately reopens the *research evidence* for tunnel convergence; it
does not retroactively make Phase 112's tested source state unqualified.

## Workstream B — reconcile roadmap phase states

Update the detailed Phase 105–112 section of `plans/roadmap.md` so it is
clearly historical/closed rather than ACTIVE.

At minimum:

- section heading says CLOSED QUALIFIED;
- Phase 108 says CLOSED QUALIFIED;
- Phase 112 says CLOSED QUALIFIED;
- Phase 107/109/111 remain CLOSED DEFER;
- Phase 110 remains CLOSED RETAIN INTERNAL;
- the top summary continues to identify `e7c0ec5...` and run
  `36955732943`.

Do not convert DEFER/RETAIN into success merely to make the table look uniform.

## Workstream C — reconcile umbrella and individual status references

Search current authority for stale strings such as:

```bash
rg -n "Phases 105.?112.*ACTIVE|Phase 112.*IN PROGRESS|Phase 108.*PLANNED / READY|final-head.*pending|Hosted.*Pending" \
  plans architecture
```

Classify each hit:

- current authority — fix;
- historical execution instruction — retain if clearly historical;
- ambiguous — rewrite to explicitly mark historical context.

Avoid broad cleanup of unrelated older campaigns.

## Workstream D — register the post-closeout follow-up correctly

Current authority should state that:

- Phases 105–112 remain CLOSED QUALIFIED as a completed campaign;
- Phase 113 is a documentation/evidence corrective only;
- Phase 114 is a separately registered tunnel convergence evidence follow-up;
- neither phase reopens DNS, honeypot, mesh, ICMP, sandbox, or YARA
  dispositions.

The existence of Phase 114 must not be described as an Eggtunnel adoption
decision.

## Verification

Because this phase is docs-only:

```bash
git diff --check
cargo fmt --all -- --check
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
```

If repository guards or docs validation provide a narrower canonical command,
use it in addition to the above.

A full `verify-full` / `verify-release` rerun is not required solely for
truthful documentation edits unless a repository guard says otherwise.

Hosted CI should run normally on the landed docs commit. A new
dependency-security proof is useful but not required to supersede the already
qualified Phase 112 implementation evidence because no dependency file may
change.

## Acceptance criteria

- no current-authority Phase 105–112 verification table says Pending for checks
  that already passed;
- global roadmap and umbrella both identify the campaign as CLOSED QUALIFIED;
- Phase 108 is no longer shown as PLANNED/READY in current roadmap authority;
- proof-bearing SHA and hosted run ID agree everywhere;
- skipped native jobs are not upgraded into passed evidence;
- Phase 114 is registered as an evidence follow-up, not an adoption;
- no production/dependency file changes.

## Rejection criteria

Reject implementation that:

- reruns or rewrites the campaign merely to fix prose;
- changes the proof-bearing SHA to the docs-only corrective commit;
- claims native ICMP/sandbox qualification from skipped jobs;
- changes any DEFER/RETAIN disposition without new evidence;
- edits unrelated historical plans in a broad status sweep;
- touches Cargo.lock, Cargo.toml, Rust source, or workflow behavior.
