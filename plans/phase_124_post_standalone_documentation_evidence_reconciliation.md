# Phase 124 Plan: Post-Standalone Documentation and Evidence Reconciliation

Status: **PLANNED / READY** (2026-10-04).

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at
`cacd44bffe097d7c62e3ddb0c5816967498a7bde`.

Related closeout:
`architecture/standalone_crate_phase123_closeout.md`.

DNS successor research:
`architecture/dns_runtime_dto_conversion_research.md`.

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
