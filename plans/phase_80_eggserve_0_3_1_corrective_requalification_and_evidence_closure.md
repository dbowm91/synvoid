# Phase 80 Plan: EggServe 0.3.1 Corrective Requalification and Evidence Closure

Status: planned; blocked on Phase 79 runtime-correctness implementation.

Registered in: `plans/roadmap.md` and `plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

Parent corrective: `plans/phase_79_eggserve_0_3_1_h1_runtime_correctness_corrective.md`.

Baseline under review: Phase 79 corrected implementation SHA, descended from the adoption commit `2242e1911d2083448371f707392fdb07f83f1bce`.

## Purpose

Requalify the corrected EggServe H1 production path, obtain truthful hosted proof, reconcile stale Phase 73–78 status/evidence, and make the terminal adoption decision.

Phase 80 supersedes the evidence/closure claim of Phase 78. It does not erase the historical Phase 78 test/performance evidence; it distinguishes what was valid from what was incomplete or incorrect.

## Entry conditions

Do not begin terminal closure until Phase 79 has:

- corrected the shutdown-driver lifetime bug;
- corrected exact-body trailer preservation;
- added the real AppServer tunnel fixture/coverage;
- removed peer-as-local endpoint fabrication;
- passed the Phase 79 local verification matrix.

Record the exact Phase 79 implementation SHA before running hosted proof.

## Track A — focused regression requalification

Re-run the corrected contracts directly, not only through broad `cargo xtask verify`:

- plaintext and TLS-H1 active-response shutdown/drain;
- plaintext and TLS-H1 active WebSocket shutdown;
- exact small body + trailers, zero-DATA + trailers, and unknown-length trailers;
- AppServer WebSocket/tunnel over the production neutral upgrade path on plaintext and TLS;
- local/remote endpoint provenance;
- per-site Date/Server matrix;
- parser-buffer/header-count/aggregate-header values above the former EggServe 0.3.0 caps;
- WAF Drop terminal response ordering;
- keep-alive/pipelining sanity;
- H2 ALPN negative guard.

Any failure in valid config support, response metadata, framing, WAF, tunnel lifecycle, or graceful shutdown is rollback-class until adjudicated.

## Track B — verify no corrective performance/resource regression

The Phase 79 fixes touch connection lifecycle and the small exact-response conversion path. Re-run the existing same-host narrow H1 performance harness sufficiently to detect an accidental common-path regression.

At minimum record:

- sequential small keep-alive latency;
- concurrent small-request throughput;
- representative request-body/streaming case;
- no-trailer exact response path;
- trailer-bearing exact response path as a functional measurement (not necessarily benchmarked against historical Hyper if no equivalent harness exists).

Do not reopen the entire Phase 78 performance campaign unless the corrective materially changes the common path. If results remain within the previously accepted envelope, reference the Phase 78 raw evidence and state that the corrective did not change the disposition.

## Track C — full repository/security/profile proof

Run the repository's current canonical commands, including:

- `cargo fmt --all -- --check`
- `cargo xtask test guards`
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci`
- `cargo nextest run -p synvoid-config --cargo-profile ci --profile ci`
- no-default-feature and `post-quantum` / `mesh` / `dns` / `mesh,dns` checks used by the prior campaign
- `cargo deny check`
- `cargo audit`
- `cargo xtask verify`

If `verify-full` and/or `verify-release` are current supported handoff commands, run them according to their clean-tree requirements and record the outcome. Do not resurrect obsolete verification commands solely because an old plan named them.

## Track D — hosted CI is mandatory and must cover the corrected runtime

The GitHub Actions run for `2242e1911d2083448371f707392fdb07f83f1bce` is not sufficient proof for Phase 80, even if it eventually succeeds, because it predates the Phase 79 runtime corrections.

Requirements:

- obtain a hosted run on the Phase 79 corrected implementation SHA, or on a later proof-bearing SHA containing exactly those runtime corrections;
- require the canonical routine CI job to finish successfully;
- record run id, job/result, SHA, and observation date;
- do not write `hosted CI green` before the run has actually completed successfully;
- if later Phase 80 work changes executable code, obtain a new hosted run for that executable state.

A docs-only metadata commit after the observed green proof may record the proof-bearing SHA/run without requiring the historical proof SHA to equal the documentation commit, provided the distinction is explicit (same convention used by earlier SynVoid closeouts).

## Track E — reconcile planning and evidence truth

Update current-state documents so they no longer contradict the repository:

- `plans/roadmap.md` top status and the Post-Phase-72 EggServe section;
- `plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`;
- Phase 73 status note so the 0.3.0 retained result, 0.3.1 GO, and later adoption are temporally clear;
- Phase 74–77 status notes only where needed to distinguish historical phase-local state from current production state;
- Phase 78 status: mark its closure claim superseded by Phases 79–80 while preserving its valid historical evidence;
- `architecture/eggserve_0_3_h1_adoption_closeout.md`: add the corrective implementation/proof section and remove/replace any unsupported hosted-CI or AppServer-completeness claim;
- `architecture/http_server.md` and relevant developer skill/AGENTS pointers if they still name Hyper as the current H1 authority.

Do not rewrite historical 0.3.0 compatibility evidence as though it described 0.3.1.

## Track F — residual separation

After corrective closure, keep these separate unless Phase 79 accidentally touches them:

- H2 `max_header_list_size(max_headers)` byte-unit compatibility review;
- pre-existing duplicate `Set-Cookie` collapse behavior;
- declared-length oversize 403 vs unknown-length 413 relabeling;
- test-only legacy Hyper differential lane retention/removal decision.

Do not use those pre-existing residuals to obscure whether the EggServe H1 corrective itself is complete.

## Required closure artifact

Extend or add a corrective closeout record that contains:

- adoption baseline `2242e191...`;
- Phase 79 implementation SHA;
- Phase 80 proof-bearing SHA;
- exact EggServe versions/checksums;
- focused regression results;
- AppServer tunnel result;
- shutdown/drain result;
- trailer-preservation result;
- performance/resource recheck summary;
- full local verification results;
- hosted CI run identity/result;
- final terminal disposition.

Preferred terminal disposition when all gates pass: `ADOPTED` with Phase 78 closure explicitly superseded by the Phase 80 corrective proof. Use `RETAINED_ROLLBACK` only if the corrected production architecture fails a required contract and the qualified Hyper rollback point must be restored.

## Acceptance criteria

- [ ] Phase 79 implementation is complete and its SHA recorded;
- [ ] all four post-review defects are directly regression-tested;
- [ ] AppServer tunnel coverage satisfies the original Phase 78 requirement;
- [ ] corrected shutdown path proves active driver futures are not cancelled by the outer worker select;
- [ ] exact-body trailers survive the EggServe boundary;
- [ ] per-site metadata/config-range/WAF/tunnel contracts remain green;
- [ ] H2/H3 remain unchanged;
- [ ] same-host performance/resource recheck shows no new rollback trigger;
- [ ] current canonical local verification is green;
- [ ] hosted CI is observed green on a SHA containing the Phase 79 corrections;
- [ ] roadmap/campaign/closeout documents are internally consistent and date/SHA truthful;
- [ ] Phase 78's premature closure claim is explicitly superseded;
- [ ] final disposition is `ADOPTED` or `RETAINED_ROLLBACK` with evidence.

## Non-goals

- No EggServe H2/H3/TLS-listener/core migration.
- No general HTTP config redesign.
- No unrelated WebSocket feature work.
- No publication/version change to EggServe unless Phase 79 discovers a genuine upstream blocker.
- No broad cleanup outside the files/evidence necessary to close this corrective line.