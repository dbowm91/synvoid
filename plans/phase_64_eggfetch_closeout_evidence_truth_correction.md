# Phase 64 Plan: Eggfetch Closeout Evidence Truth Correction

Status: detailed documentation/evidence corrective handoff plan (2026-09-22).

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Baseline reviewed: `main` at `efbe2dc154298646fc6e6f29865e0cebb93b2150`.

Runtime proof-bearing SHA remains:
`c3568ef4580a49edf222c5e4e6ce5d4dca904e81`.

Phase 63 final performance authority remains:
`architecture/eggfetch_0_2_transport_performance_requalification.md`.

Upstream follow-up now concretely registered in eggfetch:

- repository: `eggstack/eggfetch`;
- plan: `plans/native-concurrent-streaming-tail-investigation.md`;
- upstream planning registration head:
  `916521cb404d691cbb7370cfc2235a2a316abaa2`;
- upstream 0.2.0 planning baseline:
  `8959ca890ee34f4cf456aed648315322f1e83ef7`.

## Objective

Correct the remaining evidence/documentation truth defects in the otherwise
closed eggfetch 0.2 migration campaign without reopening runtime code,
performance adjudication, or transport ownership.

Two defects remain after Phase 63:

1. the closeout says Phase 63 adjudicated "10 immutable session datasets",
   while the repository contains six authoritative immutable comparison
   session directories:
   - full matrix run 1;
   - full matrix run 2;
   - concurrent-streaming persistence;
   - concurrency-2 scaling;
   - concurrency-8 scaling;
   - 64 KiB phase-split.
   The `diagnostic-sametree/` directory is explicitly non-authoritative and
   must not be counted as an immutable before/after session.

2. multiple current documents say the concurrent-streaming residual is
   "tracked upstream" without naming an actual upstream artifact. The
   follow-up is now concretely registered in `eggstack/eggfetch` as
   `plans/native-concurrent-streaming-tail-investigation.md`; SynVoid should
   reference that plan directly.

This is a documentation/evidence correction only.

## Non-goals

- No changes to production Rust code.
- No changes to the Phase 62 registry/TLS corrections.
- No changes to the Phase 63 benchmark harness or raw results.
- No new benchmark runs.
- No re-adjudication of the accepted concurrent-streaming residual.
- No SynVoid-side performance workaround.
- No new CI gate.
- No dependency/version change.
- No reopening of legacy Hyper as a production lane.
- No claim that the upstream eggfetch plan has already reproduced or fixed the
  residual.

## Workstream A — Correct the immutable-session count

Audit all current Phase 62/63 authority and summary documents for wording that
implies ten authoritative immutable sessions.

At minimum inspect:

- `architecture/eggfetch_0_2_transport_performance_requalification.md`;
- `architecture/eggfetch_0_2_transport_corrective_closeout.md`;
- `plans/phase_63_eggfetch_transport_benchmark_requalification_and_final_evidence_closeout.md`;
- `plans/eggfetch_0_2_transport_consolidation_roadmap.md`;
- `plans/roadmap.md`;
- `README.md`;
- `.opencode/skills/http_client/SKILL.md`;
- `src/http_client/AGENTS.override.md`.

Use one canonical statement:

> Phase 63 committed six authoritative immutable comparison sessions
> (two full matrices, concurrent-streaming persistence, concurrency-2,
> concurrency-8, and the 64 KiB phase-split), plus separately labeled
> same-tree diagnostics that are non-authoritative for before/after parity.

Do not convert run counts into session counts. The phase-split session has ten
lane/result runs but is one immutable comparison session.

Preserve the raw result directories and their historical metadata unchanged.

## Workstream B — Replace vague "tracked upstream" language

Where current docs say only "tracked upstream" or "upstream follow-up", replace
that wording with an explicit cross-repository reference:

`eggstack/eggfetch: plans/native-concurrent-streaming-tail-investigation.md`

Include the upstream planning baseline/registration SHA in the canonical
architecture record, but avoid spraying SHAs through every user-facing doc.

Recommended authority split:

- `architecture/eggfetch_0_2_transport_performance_requalification.md`:
  full path + upstream baseline/registration SHA;
- `.opencode/skills/http_client/SKILL.md`:
  named upstream plan path, no need for full SHA block;
- `src/http_client/AGENTS.override.md`:
  named upstream plan path;
- README/roadmaps:
  keep the accepted residual summary concise and point to the SynVoid final
  authority rather than duplicating upstream mechanics.

The wording must be precise:

- SynVoid has **accepted** the residual for its 0.2 adoption;
- eggfetch has an **active investigation plan**;
- eggfetch has **not yet proven** the mechanism or shipped a correction;
- no SynVoid workaround is planned unless future evidence materially changes
  the tradeoff.

## Workstream C — Preserve performance adjudication boundaries

Do not rewrite Phase 63's result into stronger claims.

The final record must continue to say:

- H1 small-request concurrency did not reproduce the Phase 62 ~20% loss under
  the stronger protocol;
- true sequential streaming is broadly parity within host spread;
- synchronized 64 KiB streaming at concurrency >=4 retains a quantified tail
  residual;
- p50 remains near/equal while p95/p99 worsen in that residual;
- the residual is accepted for SynVoid because no local avoidable cost was
  identified and the single-transport maintenance/security benefit remains;
- the upstream plan is an investigation, not proof that eggfetch is at fault.

Do not collapse "accepted residual" into "parity".

## Workstream D — Reconcile authority wording

Ensure the authority chain remains unambiguous:

1. Phase 62 closeout:
   runtime policy/TLS correction authority.
2. Phase 63 record:
   final SynVoid performance/reproducibility authority.
3. Phase 64:
   documentation/evidence truth correction only.
4. eggfetch upstream plan:
   future ownership investigation for the accepted residual.

Phase 64 must not supersede the measured Phase 63 evidence; it only corrects
its count/reference wording.

Update Phase 64 status to complete only after the consistency sweep is clean.

## Workstream E — Consistency sweep

Search for at least:

```text
10 immutable session
10 immutable
tracked upstream
upstream follow-up
concurrent-streaming
stream-concurrent
Phase 63
```

Classify every hit as:

- historical plan statement;
- raw benchmark/result evidence;
- current authority;
- current operational guidance.

Historical descriptions of what Phase 63 intended to do may remain if they
are clearly historical. Current authority/guidance must use the corrected
count and concrete upstream reference.

Do not modify unrelated uses of "tracked" elsewhere in the repository.

## Verification

Because this is a docs/evidence-only pass:

1. prove the diff contains no production/test/benchmark source changes;
2. run formatting/link/docs checks required by the repository for
   documentation changes;
3. run `cargo xtask test guards` only if plan/architecture guards inspect
   these files;
4. run `cargo xtask verify` if the repository convention requires a full
   ordinary validation on docs-only descendants;
5. do not rerun transport benchmarks merely to correct prose.

Record the exact proof-bearing docs SHA.

The existing Phase 62 full/release runtime qualification remains bound to
`c3568ef4...`; do not imply `verify-full`/release qualification moved to
the Phase 64 docs-only commit unless those commands are actually rerun.

## Acceptance criteria

Phase 64 is complete only when:

- [ ] no current authority claims "10 immutable session datasets";
- [ ] the authoritative count is six immutable comparison sessions;
- [ ] same-tree diagnostics remain explicitly non-authoritative;
- [ ] "tracked upstream" references name the concrete eggfetch plan;
- [ ] SynVoid does not claim the upstream mechanism is already proven;
- [ ] the accepted concurrent-streaming residual remains quantified/labeled;
- [ ] no production, test, or benchmark source changed;
- [ ] Phase 62 runtime authority and Phase 63 performance authority remain
      intact;
- [ ] `plans/roadmap.md` and the eggfetch campaign roadmap show Phase 64 as
      the final docs/evidence correction;
- [ ] the final docs-only SHA and validation result are recorded.

## Rejection criteria

Reject closure if the pass:

- edits raw benchmark JSON/results to make counts match prose;
- counts same-tree diagnostics as immutable before/after evidence;
- changes the accepted residual into an unqualified parity claim;
- claims the eggfetch cause is known before upstream reproduction;
- adds a SynVoid runtime workaround;
- reruns/rewrites benchmarks without a new performance plan;
- changes the runtime proof-bearing SHA;
- creates another performance campaign for what is only a documentation
  correction.

## Expected terminal state

After Phase 64:

- Phases 58-63 remain the completed eggfetch migration/runtime/performance
  campaign;
- Phase 64 is a final docs/evidence correction;
- production remains on eggfetch 0.2;
- one accepted concurrent-streaming tail residual remains;
- the residual has a concrete upstream eggfetch investigation plan;
- SynVoid has no active local implementation work for this campaign.
