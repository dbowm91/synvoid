# Phase 124 Plan: Post-Standalone Documentation and Evidence Reconciliation

Status: **CLOSED QUALIFIED** (2026-10-04; docs/evidence only; closeout
`architecture/standalone_crate_phase124_closeout.md`; `git diff --check` clean,
`cargo fmt --all -- --check` passed, `synvoid-repo-guards` passed,
`cargo xtask verify` 10/10 passed in 1002.1s; no production/dependency change;
no successor plan unblocked).

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at
`cacd44bffe097d7c62e3ddb0c5816967498a7bde`.

Related closeout:
`architecture/standalone_crate_phase123_closeout.md`.

Phase 124 closeout:
`architecture/standalone_crate_phase124_closeout.md`.

DNS successor research:
`architecture/dns_runtime_dto_conversion_research.md`.

Outcome summary: the plan's premise that no completed merge-head run was
visible is obsolete. Hosted CI run `37218651222` passed `ci` and
`dependency-security` on merge head `cacd44bf`, alongside the campaign-branch
run `37064917481` on `f8118214`; both are recorded distinctly and neither is
relabeled as the other. Phases 115–123 keep their exact terminal dispositions.
Architecture, roadmap, umbrella, historical supersession notes, the DNS
research pointer and actionable agent guidance were reconciled; the release
policy, final surface audit, crate granularity audit, `docs/releasing.md` and
the standalone candidate registry were re-checked and left unchanged. The
`architecture/overview.md` workspace-count contradiction was corrected against
`cargo metadata` (53 members, 45 crates under `crates/`).

## Goal

Reconcile current-authority documentation after the Phase 115–123 standalone
campaign merged to `main`, without changing production Rust, dependency
topology, feature behavior, package classes, or historical evidence.

This pass must leave one unambiguous current story:

- the standalone campaign is closed;
- exact branch-head CI passed at `f81182149889e21c4908b7ee38c74bc6b4518f6b`;
- the merged `main` head is `cacd44bffe097d7c62e3ddb0c5816967498a7bde`;
- branch-head proof is not silently relabeled as merge-head exact-SHA proof;
- DNS/mesh remain DEFER, sandbox remains RETAIN;
- honeypot, DNSSEC keystore and mesh protocol are standalone-capable class 2
  only;
- `synvoid-rate-limit` remains the sole class-3 crate;
- native macOS honeypot and live PKCS#11/HSM evidence remain residuals.

## Known documentation defects

### 1. Exact-SHA CI wording

`plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md` still contain wording that
exact-SHA hosted CI "remains a post-push check".

That is stale for the campaign branch: Phase 123 records a successful exact-head
workflow on `f8118214` for both Verify and dependency-security.

As of this plan's baseline, the GitHub connector exposes no completed workflow
run/status directly on the new merge commit `cacd44bf`. Therefore the cleanup
must distinguish:

- **campaign branch exact-SHA proof:** passed at `f8118214`;
- **current merged-main exact-SHA proof:** record only if a real run exists;
  otherwise state that it is not yet evidenced.

Do not convert absence of a status object into either success or failure.

**Resolved during execution:** a real run was found. `cacd44bf` carries
workflow `CI` run `37218651222` (`ci`/Verify and `dependency-security` both
success; both native qualification jobs skipped by their false-by-default
inputs). Both proofs are recorded distinctly. The genuinely red pre-merge runs
on first parent `fd8fc2a8` (push `37149285202`, daily schedule `37200443692`,
`RUSTSEC-2026-0325/0326/0327`) are recorded as historical and superseded,
because the merge carries the Phase 123 Wasmtime `48.0.5` remediation that
clears them without any advisory ignore.

### 2. Current architecture summary lags Phase 123

`architecture/overview.md` still describes:

- honeypot primarily through the Phase 107 extraction-DEFER result;
- DNS through Phase 109's coupling verdict;
- mesh through Phase 110;
- DNSSEC keystore without its Phase 122 class-2 package hardening;
- mesh protocol without the Phase 122 standalone class-2 result.

These historical decisions remain true at their dates, but the current overview
needs Phase 121–123 supersession/status pointers.

### 3. Historical qualification records need supersession pointers

Do not rewrite historical evidence. Where a historical document is likely to be
read as current authority, append a short supersession note:

- Phase 107 honeypot qualification -> Phase 121/123 package hardening;
- Phase 109 DNS readiness -> Phase 116/117 DEFER and current runtime-DTO research;
- Phase 110 mesh boundary -> Phase 118/119 DEFER;
- process-sandbox extraction records -> Phase 120 RETAIN where useful.

The historical result itself must remain intact.

### 4. Release/classification consistency

Re-check, rather than blindly rewrite:

- `architecture/public_crate_release_policy.md`;
- `architecture/final_surface_audit.md`;
- `architecture/crate_granularity_audit.md`;
- `docs/releasing.md`;
- standalone candidate registry/metadata;
- README/public crate table if present.

These already contain Phase 123 updates in the baseline and should only change if
a contradiction is found.

### 5. Agent/skill knowledge

Review `AGENTS.md` and DNS/package-related skills for current ownership facts.

Do not add campaign history to agent files merely for completeness. Update only
actionable guidance, particularly:

- `src/dns/` remains a pure facade;
- persisted DNS config remains in `synvoid-config`;
- future config-to-runtime adapters belong in composition (`src/server/`), not
  the facade;
- honeypot/DNSSEC-keystore/mesh-protocol are class-2 packaged candidates, not
  public support promises.

## Workstream A — terminal status reconciliation

Update current roadmaps so:

- Phases 115–123 are uniformly CLOSED with their exact terminal dispositions;
- the successful `f8118214` hosted run is recorded once consistently;
- the Phase 115 interrupted local `cargo xtask verify` remains a truthful
  historical fact, while the later campaign-head Verify run is identified as
  terminal campaign evidence;
- no text says Phase 117/119 are merely "blocked" when their plan files now say
  CLOSED DEFER due to predecessor failure;
- no successor extraction/publication plan is implied.

## Workstream B — merged-main evidence check

Check Actions/status for `cacd44bf`.

If a completed exact-merge-head run exists:

- record workflow/run ID, jobs and conclusion;
- update terminal evidence accordingly.

If it does not exist:

- say so explicitly in current-authority docs;
- do not trigger or invent a qualification run as a docs-only side effect unless
  separately requested;
- preserve `f8118214` as the tested campaign implementation head.

## Workstream C — architecture summary refresh

Reconcile current state in:

- `architecture/overview.md`;
- `architecture/final_surface_audit.md` if needed;
- `architecture/crate_granularity_audit.md` if needed;
- `architecture/public_crate_release_policy.md` if needed;
- `docs/releasing.md` if needed.

The overview should summarize the final package decisions, not reproduce the
entire campaign.

## Workstream D — targeted historical supersession notes

Append only minimal current-status pointers to historical docs that are commonly
used as architecture authorities.

Do not change old proof SHAs, old test counts, or contemporaneous DEFER/RETAIN
reasoning.

## Workstream E — DNS next-work pointer

Link
`architecture/dns_runtime_dto_conversion_research.md`
from the current DNS architecture/readiness documentation.

The pointer must say research is complete but implementation is not registered
under Phase 124. Do not turn documentation cleanup into DNS source work.

## Workstream F — stale-status search

Search current-authority docs for at least:

```text
ACTIVE / REGISTERED
PLANNED / READY
BLOCKED ON PHASE 116
BLOCKED ON PHASE 118
post-push check
Phase 107
Phase 109
Phase 110
external_support
class 2
class 3
```

Classify every hit as:

- historical and intentionally retained;
- current and correct;
- stale and corrected.

Record the classification in the Phase 124 closeout.

## Execution record (2026-10-04)

Workstream B — merged-main evidence:

- `gh run view 37218651222` confirms a real completed exact-merge-head run on
  `cacd44bffe097d7c62e3ddb0c5816967498a7bde`: `ci`/Verify success and
  `dependency-security` success; `icmp-native-qualification` and
  `sandbox-native-qualification` skipped. The plan's "no visible run"
  premise no longer holds, so the Workstream B positive branch applied.
- Pre-merge first parent `fd8fc2a8` is genuinely red (push `37149285202`;
  daily schedule `37200443692`) on `RUSTSEC-2026-0325/0326/0327` from the
  pre-campaign Wasmtime pin. Recorded as historical and superseded: the merge
  carries the Phase 123 `third-party/yara-x-compat` Wasmtime `48.0.5` pin, and
  the merge-head `dependency-security` job is green with `deny.toml` still
  holding exactly two advisory ignores.

Workstream A — terminal status:

- `plans/roadmap.md` status header, campaign section, Phase 115/123 lanes and
  the Phase 124 registration section rewritten; Phases 115–123 now carry a
  uniform terminal-disposition list and both exact-SHA proofs.
- `plans/standalone_crate_generalization_roadmap.md` header, successor-gate
  paragraph and Phase 124 block updated identically.
- The Phase 115 interrupted local `cargo xtask verify` remains stated as a
  truthful historical fact and is explicitly separated from the terminal hosted
  Verify evidence.

Workstream C — architecture summary:

- `architecture/overview.md` honeypot / DNSSEC-keystore / mesh / DNS rows now
  carry Phase 121/122/123 and Phase 116/117/118/119 status; Documentation Map
  links the standalone contract and the Phase 123/124 closeouts.
- Found and fixed an unrelated-but-real contradiction in the same file: the
  workspace shape said "51 members / 43 crates under `crates/`" in one place
  and "47 crates" in another. `cargo metadata --no-deps` reports 53 members
  with 45 `synvoid-*` crates under `crates/` (47 `synvoid-*` packages total
  including `synvoid-fuzz` and `synvoid-repo-guards`); both lines now agree
  with the manifest and `AGENTS.md`.
- `architecture/public_crate_release_policy.md`,
  `architecture/final_surface_audit.md`, `architecture/crate_granularity_audit.md`,
  `docs/releasing.md`, `architecture/standalone_crate_candidates.toml` and the
  root README were re-checked and left unchanged — no contradiction found.

Workstream D — historical supersession:

- Appended current-status pointers to
  `architecture/honeypot_standalone_qualification_phase107.md`,
  `architecture/dns_application_neutral_readiness_phase109.md`,
  `architecture/mesh_boundary_decomposition_phase110.md` and
  `architecture/process_sandbox_corrective_closeout.md`. No historical result,
  test count, proof SHA or contemporaneous reasoning was altered.

Workstream E — DNS next-work pointer:

- `architecture/dns_runtime_dto_conversion_research.md` linked from
  `architecture/dns.md`, `architecture/overview.md` and the Phase 109 readiness
  record, each marked RESEARCH COMPLETE / IMPLEMENTATION NOT REGISTERED. No DNS
  source touched.

Workstream F — stale-status search:

- Full classification ledger recorded in
  `architecture/standalone_crate_phase124_closeout.md` §7. Stale and corrected:
  both `post-push check` statements, the Phase 124 `ACTIVE / REGISTERED` and
  `PLANNED / READY` statuses, and the Phase 107/109/110 references in the
  overview. Historical and retained: the plan's own defect text and search
  terms, and the Phase 106/113/118 contemporaneous execution lines. Current and
  unchanged: every `external_support` and `class 2`/`class 3` statement —
  `synvoid-rate-limit` remains the only class-3 crate.

Workstream G — agent/skill knowledge:

- `AGENTS.md` public-libraries index extended to Phase 124; new DNS
  boundary-research index line carrying the `src/server/` vs `src/dns/` pure
  facade rule.
- `crates/synvoid-dns/AGENTS.override.md` gained a crate-boundary-status
  section.
- `crates/synvoid-honeypot/AGENTS.override.md` and
  `.opencode/skills/dns_dnssec/SKILL.md` reviewed; neither makes a stale
  class/support claim, so neither was changed.

Verification:

- `git diff --check` clean.
- `cargo fmt --all -- --check` passed.
- `cargo test -p synvoid-repo-guards --profile ci` passed.
- `cargo xtask verify` passed: 10 steps, 10 passed, 0 failed, 0 skipped
  (1002.1s).
- `verify-full` / `verify-release` deliberately not rerun: docs-only, no guard
  requires them, and the retained exact tested SHAs are not replaced by a docs
  commit.
- Changed files are documentation and agent-guidance only; no
  `Cargo.toml`, `Cargo.lock`, Rust source, workflow, support tier or package
  metadata changed.

Successor status: **no future plan is unblocked.** Phases 115–123 dispositions
are unchanged, the DNS runtime-DTO research is recorded rather than registered,
and no Phase 125 implementation plan exists.

## Verification

This phase is documentation/evidence only.

Minimum:

```bash
git diff --check
cargo fmt --all -- --check
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
```

If `cargo xtask verify` is not rerun because the implementation tree is
unchanged and an exact tested campaign SHA is deliberately retained, record that
decision precisely and run the focused documentation/repository guards instead.
Do not claim a check that did not run.

No `Cargo.toml`, `Cargo.lock`, Rust source, workflow, support tier or package
metadata should change in this phase.

## Acceptance criteria

- no current-authority roadmap says campaign CI is still awaiting post-push proof
  while also citing the successful `f8118214` run;
- branch-head versus merge-head evidence is explicit;
- architecture overview reflects Phase 123 terminal crate classifications;
- historical Phase 107/109/110 records remain historically truthful;
- no class-2 package is described as class 3 or externally supported;
- DNS runtime-DTO research is discoverable without being registered as
  implementation;
- no production/dependency file changes.

## Rejection criteria

Reject a closeout that:

- rewrites historical closeout evidence to make it look current;
- claims `cacd44bf` exact-SHA CI without a real run;
- uses documentation cleanup to alter DNS runtime/config APIs;
- promotes/publishes a package;
- changes class/support status;
- creates Phase 125 implementation work implicitly.
