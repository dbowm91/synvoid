# Track 3 Documentation Closeout Corrective Plan

Status: detailed documentation-only handoff plan.

Scope: final bookkeeping/documentation reconciliation after the Track 3 post-closure corrective implementation and green verification evidence on `main` at `206726706dc66a556829585673b18c8e17370b46`.

Primary goal: make the canonical roadmap and prior corrective-plan metadata describe the already-completed repository state without contradictory active-work language or retained pre-Track-3 current-state claims.

This is not an implementation, architecture, CI, fuzzing, testing, packaging, or release-hardening pass. The underlying corrective work is already complete and evidenced in `architecture/track3_post_closure_corrective_report.md`.

## Context

The Track 3 post-closure corrective implementation landed in `29ae0b4fc3a8155ebe16029dd99534c4f92f9571`, with later closeout commits recording the implementation SHA and successful remote CI. Current `main` is `206726706dc66a556829585673b18c8e17370b46`.

Substantive acceptance evidence is already green:

- `cargo xtask verify-full`: 7/7 steps pass;
- `cargo xtask verify-release`: 9/9 steps pass;
- current remote GitHub Actions `CI` run is green;
- `http_chunked_framing`, `jail_ipc_frame_decode`, `http_routing_matcher`, and `config_parse_validation` each completed the declared `-runs=1000` bounded smoke standard with no crash/hang;
- config parsing fuzzing uses production-equivalent `MainConfig::from_toml_str` / `SiteConfig::from_toml_str` seams;
- `synvoid::serder` was removed and its breaking pre-1.0 surface change recorded;
- current CI/fuzz documentation describes the actual single-workflow topology.

The remaining defect is documentation state, not product behavior:

1. `plans/track3_post_closure_corrective.md` still has `Status: detailed corrective handoff plan.` even though all of its acceptance criteria have been satisfied and the closure report exists.
2. `plans/roadmap.md` says the post-Track-3 corrective pass is the only active handoff item, even though it is complete.
3. `plans/roadmap.md` retains a pre-Track-3 paragraph under `Current Architectural Position` claiming enforcement overlap, mixed root ownership, jail-process stubs, and fragmented distributed-state semantics, then appends a blockquote saying the newer state supersedes it. The prior corrective plan explicitly required replacement, not preservation of contradictory current-state prose.
4. The roadmap should reach a terminal Track 3 state with no implied active Track 3/corrective implementation work.

## Non-Goals

- Do not change Rust source, manifests, build scripts, CI workflows, fuzz targets, tests, benchmarks, packaging, or release commands.
- Do not create Track 4, Phase 25, or another architecture-hardening phase.
- Do not reopen any Track 3 technical decision or ownership boundary.
- Do not rerun expensive verification solely for prose-only edits unless repository policy requires it.
- Do not rewrite historical phase plans/results into ahistorical documents. Preserve historical evidence where it is clearly labeled as historical.
- Do not remove the prior corrective plan or closure report; mark their status accurately and keep them as handoff/history artifacts.
- Do not introduce new documentation tax such as another permanent status ledger solely for this closeout.

## Workstream A: Mark the Prior Corrective Plan Complete

Update `plans/track3_post_closure_corrective.md` metadata at the top of the file.

Replace the open-plan status with an explicit completed status, for example:

```text
Status: complete (2026-09-09). Closure evidence: `architecture/track3_post_closure_corrective_report.md`. Final closeout HEAD: `206726706dc66a556829585673b18c8e17370b46`.
```

Requirements:

- identify the closure report as the canonical evidence artifact;
- identify the final closeout revision or current equivalent revision;
- do not rewrite the body of the plan into a result report;
- preserve acceptance/rejection criteria as historical implementation guidance;
- optionally add a one-sentence note immediately after the status saying the body below is the executed handoff specification.

Do not change technical requirements merely because they have now been completed.

## Workstream B: Put `plans/roadmap.md` Into a Terminal Track 3 State

### B1. Fix the roadmap status line

Replace:

```text
The only active handoff item is the Track 3 post-closure corrective pass ...
```

with terminal wording that states:

- Tracks 1, 2, and 3 are complete;
- the Track 3 post-closure corrective pass is also complete;
- no active Track 3 architecture/corrective handoff remains.

Do not imply that the entire SynVoid project has no future work. The scope is specifically this architecture-hardening/convergence line.

Preferred semantic shape:

```text
Status: extended roadmap complete through Track 3 and its post-closure corrective pass. No active handoff remains in this roadmap.
```

Exact wording may vary, but it must not advertise already-executed work as active.

### B2. Replace the stale `Current Architectural Position` prose

Delete the obsolete current-state paragraph that says:

- enforcement semantics still overlap;
- highest-coupling root modules remain mixed;
- process-jail modes are fail-closed stubs;
- distributed-state semantics remain fragmented;
- convergence work still needs adversarial/performance evidence.

Also remove the temporary blockquote mechanism that says the new paragraph "supersedes" the obsolete paragraph.

Replace both with one direct current-state section describing the repository after Track 3 plus the corrective pass. It should state, compactly:

- canonical terminal enforcement semantics are established;
- auth/challenge domain ownership is canonical outside the root facade;
- WAF and HTTP ownership boundaries are explicit and guarded;
- admin/plugin are deliberate application-composition owners;
- jail IPC is operational with bounded supervised execution and fail-closed required-isolation semantics;
- distributed-state authority/partition contracts are explicit;
- zero active `split_required` modules remain;
- config parse/validation is covered by the final high-value fuzz target;
- stale `serder` root surface is removed;
- routine CI remains one Ubuntu `cargo xtask verify` job;
- full/release verification and final bounded fuzz evidence are recorded in `architecture/track3_post_closure_corrective_report.md`.

Keep this section concise. The roadmap should summarize outcomes, not duplicate architecture reports.

### B3. Add corrective-pass closeout reference

Near `## Roadmap Status` or the Track 3 closeout text, add a compact reference such as:

```text
Post-Track-3 corrective closure: complete; see `plans/track3_post_closure_corrective.md` and `architecture/track3_post_closure_corrective_report.md`.
```

The final status area should have one unambiguous interpretation: this roadmap line is closed.

## Workstream C: Check Canonical Current-State Documentation for Status Drift

This workstream is audit-first. Only edit files that contain present-tense/current-state contradictions.

Search:

```bash
rg -n "only active handoff|active handoff|Track 3 is planned|ready for implementation|post-closure corrective pass.*active" \
  plans/roadmap.md plans/track3_post_closure_corrective.md architecture docs AGENTS.md

rg -n "enforcement semantics still overlap|highest-coupling root modules remain mixed|process-jail modes are fail-closed stubs|distributed-state consistency guarantees are documented in several places" \
  plans/roadmap.md architecture docs AGENTS.md

rg -n "Track 3.*complete|post-closure corrective" \
  plans/roadmap.md architecture/track3_post_closure_corrective_report.md \
  architecture/release_hardening_report.md AGENTS.md
```

Classification rules:

- `plans/roadmap.md`: must be current and internally consistent.
- `plans/track3_post_closure_corrective.md`: may retain historical instructions, but its metadata must clearly state completion.
- `architecture/track3_post_closure_corrective_report.md`: canonical result/evidence artifact; do not rewrite unless an actual factual error is found.
- historical phase plans/results: may describe earlier states without modification when their historical context is clear.
- current operator/architecture docs: fix only if they still present superseded work as current.

Do not perform broad editorial cleanup unrelated to Track 3 status truthfulness.

## Workstream D: Minimal Verification for Documentation-Only Changes

Because this pass is documentation-only, use proportionate verification.

Required:

```bash
rg -n "only active handoff|Track 3 is planned|ready for implementation" \
  plans/roadmap.md plans/track3_post_closure_corrective.md architecture docs AGENTS.md

rg -n "enforcement semantics still overlap|highest-coupling root modules remain mixed|process-jail modes are fail-closed stubs|distributed-state consistency guarantees are documented in several places" \
  plans/roadmap.md

cargo test -p synvoid-repo-guards
```

If the repository has a cheaper documentation/path-reference guard that is not already included in `synvoid-repo-guards`, run it as well.

Do not run `cargo xtask verify-full`, `cargo xtask verify-release`, fuzzing, Criterion, or stress tests solely for these prose/status edits unless a changed file unexpectedly affects generated/validated code paths.

If any standard path/documentation guard fails because the new plan or references are not registered correctly, fix the documentation/reference defect and rerun the focused guard.

## Expected Files to Change

Required:

- `plans/track3_post_closure_corrective.md`
- `plans/roadmap.md`

Conditional only if current-state contradictions are discovered:

- `architecture/track3_post_closure_corrective_report.md`
- `architecture/release_hardening_report.md`
- `AGENTS.md`
- other current architecture/operator docs directly implicated by the focused searches

The new handoff file itself is:

- `plans/track3_documentation_closeout_corrective.md`

No source-code or workflow files should change.

## Acceptance Criteria

This documentation corrective pass is complete only when all of the following are true:

1. `plans/track3_post_closure_corrective.md` explicitly reports completed status and references `architecture/track3_post_closure_corrective_report.md` as closure evidence.
2. `plans/roadmap.md` does not describe the completed corrective pass as active work.
3. `plans/roadmap.md` contains one direct, current `Current Architectural Position` description; the obsolete pre-Track-3 risk paragraph and "supersedes" workaround are gone.
4. The roadmap states that Tracks 1–3 and the Track 3 post-closure corrective pass are complete, with no active handoff remaining in this roadmap.
5. The roadmap links the prior corrective plan and closure report without duplicating their evidence.
6. Focused repository searches find no unlabeled current-state claim that Track 3 is planned, ready for implementation, or awaiting its already-completed corrective pass.
7. Focused searches find no stale current-state claim in the roadmap that jail IPC is still a stub, WAF/HTTP/root ownership remains unresolved, or the canonical enforcement/distributed-state contracts remain outstanding.
8. Historical plan/result documents are not rewritten merely to erase history.
9. `cargo test -p synvoid-repo-guards` passes after the documentation changes.
10. No Rust source, CI workflow, fuzz target, benchmark, package boundary, or architecture contract changes as part of this pass.
11. No new roadmap phase/track is created for this bookkeeping work.

## Rejection Criteria

Reject the closeout if it:

- leaves the roadmap saying the completed corrective pass is active;
- keeps contradictory pre-Track-3 current-state prose and merely adds another superseding note;
- marks the prior corrective plan complete without linking its evidence report;
- rewrites historical plans/results so they falsely appear to have known the final state at the time;
- performs unrelated documentation cleanup that obscures reviewability;
- touches code, CI, fuzzing, benchmarks, or package structure without a newly discovered concrete defect requiring a separate plan;
- runs another broad architecture phase instead of closing the two remaining documentation-state defects.

## Handoff Order

Execute serially:

1. Update `plans/track3_post_closure_corrective.md` status metadata only.
2. Rewrite the roadmap status line and `Current Architectural Position` into terminal current-state prose.
3. Add the compact corrective-closeout reference in the roadmap final status section.
4. Run the focused status/stale-language searches and correct only current-state contradictions.
5. Run `cargo test -p synvoid-repo-guards` (plus any separate lightweight docs/path guard if required).
6. Review the final diff and confirm that only documentation/planning files changed.
7. Commit as one small documentation closeout change if practical.

## Final Acceptance Statement

The intended final state is simple: the architecture-hardening roadmap is complete through Track 3, its post-closure corrective implementation is complete and evidenced, no active Track 3 handoff remains, and no canonical current-state document simultaneously describes the pre-Track-3 problems as still outstanding.
