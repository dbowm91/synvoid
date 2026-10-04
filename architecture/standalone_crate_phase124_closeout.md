# Phase 124 Closeout — Post-Standalone Documentation and Evidence Reconciliation

Plan: `plans/phase_124_post_standalone_documentation_evidence_reconciliation.md`.
Date: 2026-10-04.
Planning baseline: `main` at `cacd44bffe097d7c62e3ddb0c5816967498a7bde`
(PR #51 merge head).
Disposition: **CLOSED QUALIFIED**. Documentation/evidence only. No Rust
source, manifest, lockfile, workflow, package metadata, support tier or
dependency topology changed. No phase disposition was converted, no package was
promoted or published, and no successor plan was created.

The standalone-capable crate campaign (Phases 115–123) is closed with its
terminal decisions unchanged:

| Phase | Terminal disposition |
|---|---|
| 115 | CLOSED / ROUTINE QUALIFICATION DEFERRED (local `cargo xtask verify` interrupted during failure-injection compile) |
| 116 | CLOSED DEFER (DNS runtime-config/core neutralization not delivered) |
| 117 | CLOSED DEFER — Phase 116 predecessor not delivered |
| 118 | CLOSED DEFER (mesh application-dispatch capability inversion not delivered) |
| 119 | CLOSED DEFER — Phase 118 predecessor not delivered |
| 120 | CLOSED RETAIN (no proven dependency-reachability reduction; no sandbox crate) |
| 121 | CLOSED DEFER — native macOS qualification unavailable (Linux package proof passed) |
| 122 | CLOSED CLASS 2 — live HSM provider deferred; RSA public promotion blocked |
| 123 | CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS (no class-3 or repository trigger) |

## 1. Evidence reconciliation: branch head is not merge head

The plan was written when no completed hosted run was visible for the merge
commit. That premise is now obsolete: a real run exists and is recorded below.
Branch-head and merge-head proof are kept distinct and are **not** interchanged.

| Proof | SHA | Workflow run | Jobs | Conclusion |
|---|---|---|---|---|
| Campaign branch head | `f81182149889e21c4908b7ee38c74bc6b4518f6b` | CI `37064917481` (`workflow_dispatch`, 2026-10-02) | `ci`/Verify, `dependency-security` | success; both native jobs skipped |
| Merged `main` head (PR #51) | `cacd44bffe097d7c62e3ddb0c5816967498a7bde` | CI `37218651222` (`push`, 2026-10-04) | `ci`/Verify, `dependency-security` | success; both native jobs skipped |

The merge-head run is the current-authority proof for `main`; `f8118214`
remains the tested campaign implementation head. `f8118214` is not relabeled as
merge-head proof, and the merge-head run does not retroactively re-qualify any
skipped native job.

Both runs skipped `icmp-native-qualification` and
`sandbox-native-qualification` through their false-by-default inputs. Skipped
jobs are not upgraded into passed evidence anywhere in this reconciliation.

### 1.1 Pre-merge red runs (historical, superseded)

The merge's first parent, `fd8fc2a816a5a6c4bda8d2f3843299d2f567897e`, was
genuinely red twice:

| Run | Event | Conclusion | Cause |
|---|---|---|---|
| `37149285202` | `push` (2026-10-03) | failure | `RUSTSEC-2026-0325`, `RUSTSEC-2026-0326`, `RUSTSEC-2026-0327` against the pre-campaign Wasmtime pin |
| `37200443692` | `schedule` (2026-10-04) | failure | same three advisories in `dependency-security` and `ci` |

Those are the runs that made "exact-SHA hosted CI remains a post-push check"
true at the time. The Phase 123 Wasmtime `48.0.5` remediation for the
manifest-only YARA compatibility fork
(`third-party/yara-x-compat/Cargo.toml`) landed with the campaign, so the merge
head resolves all three with **no advisory ignore**. `deny.toml` still carries
exactly two ignores (`RUSTSEC-2023-0071`, `RUSTSEC-2026-0235`), unchanged by
this phase. The merge-head `dependency-security` job succeeded, which is the
authoritative evidence that no unignored advisory remains.

## 2. Terminal status reconciliation (Workstream A)

| File | Change |
|---|---|
| `plans/roadmap.md` | Status header: Phase 124 `ACTIVE / REGISTERED` -> `CLOSED QUALIFIED` with closeout link. Campaign section: "Exact-SHA hosted CI remains a post-push check" replaced by the two-proof table. Added a uniform terminal-disposition list for Phases 115–123. Phase 123 lane records the merge-head run alongside the branch run. Phase 115 lane now separates the truthful interrupted local `cargo xtask verify` from the terminal hosted Verify evidence. Phase 124 registration section rewritten as a closed record with scope-as-executed, evidence, successor status and observed constraints. |
| `plans/standalone_crate_generalization_roadmap.md` | Header status replaces the post-push-check wording with both proofs. Successor-gate paragraph no longer lists exact-SHA hosted CI as an open external gate. Phase 124 block marked CLOSED QUALIFIED with closeout link. DNS successor research pointer retained and labelled research-only. |
| `plans/phase_124_*.md` | Status set to CLOSED QUALIFIED with the executed scope, verification record and successor determination. |

## 3. Architecture summary refresh (Workstream C)

`architecture/overview.md` previously described honeypot through the Phase 107
extraction-DEFER result, DNS through Phase 109, mesh through Phase 110, and
listed DNSSEC keystore and mesh protocol without their Phase 122 package
result. Those historical decisions remain true at their dates; the overview
now carries the superseding status:

- **Honeypot** — Phase 121 package hardening plus a Linux packaged-source
  consumer proof; class 2 with `external_support = false`; native macOS
  qualification still unavailable; extraction still DEFER.
- **DNSSEC keystore** — Phase 122 standalone class 2 with
  `external_support = false`; live PKCS#11/HSM deferred; public promotion
  blocked by the unresolved RSA advisory.
- **Mesh** — Phase 110 RETAIN INTERNAL reinforced by Phases 118/119 CLOSED
  DEFER and the absence of any `synvoid-mesh-runtime` crate; the
  `synvoid-mesh-protocol` leaf is Phase 122 class 2, `external_support = false`.
- **DNS** — class 1; Phases 116/117 CLOSED DEFER; the persisted-config ->
  runtime-DTO split was not delivered; research pointer added.

Documentation Map: the standalone packaging contract and the Phase 123/124
closeouts are now reachable from the "Boundaries (must-know)" row.

### 3.1 Workspace-shape contradiction found and corrected

The same file carried two conflicting workspace counts. Line 38 said 47
`synvoid-*` library crates under `crates/` while the layout summary said "51
members — ... 43 `synvoid-*` crates under `crates/`".

`cargo metadata --no-deps` at this baseline reports **53 workspace members**:
root app, 45 `synvoid-*` crates under `crates/`, `admin-ui`, `pqc`, 2 examples,
`fuzz`, `tools/{xtask,synvoid-repo-guards}` — i.e. 47 `synvoid-*` packages in
total once `synvoid-fuzz` and `synvoid-repo-guards` are counted. Both lines were
corrected to agree with the manifest and with `AGENTS.md`. This is the only
non-standalone-campaign correction in the overview, and it changes no
dependency topology.

### 3.2 Records re-checked and deliberately left unchanged

Per the plan's "re-check, rather than blindly rewrite" instruction, these were
audited for contradiction and found already correct in the baseline:

- `architecture/public_crate_release_policy.md` — already carries the Phase 123
  standalone decision (no class-3 addition, `external_support=false` for the
  three leaves, ICMP/YARA/proxy-cache/tarpit/filter/jail-protocol/
  native-extension gates produced no follow-on plan);
- `architecture/final_surface_audit.md` and
  `architecture/crate_granularity_audit.md` — no stale class or support-tier
  claim found (`crate_granularity_audit.md` is already labelled superseded by
  `crate_boundary_reuse_closeout.md`);
- `docs/releasing.md` — external-support order still names only
  `synvoid-rate-limit`, as enforced by
  `tools/synvoid-repo-guards/tests/public_crate_release_policy.rs`;
- `architecture/standalone_crate_candidates.toml` — registry holds exactly the
  three Phase 121/122 packages with empty `allowed_siblings`; consistent with
  the guard `standalone_candidate_contract.rs`;
- root `README.md` — external-support boundary already stated.

## 4. Historical supersession notes (Workstream D)

Appended minimal current-status pointers without altering any historical
evidence, test count, proof SHA or contemporaneous DEFER/RETAIN reasoning:

| Historical doc | Pointer added |
|---|---|
| `architecture/honeypot_standalone_qualification_phase107.md` | Phase 121 package hardening + Linux consumer proof; class 2 `external_support=false`; extraction still DEFER |
| `architecture/dns_application_neutral_readiness_phase109.md` | Phases 116/117 CLOSED DEFER; Phase 123 reconfirmation; runtime-DTO research pointer |
| `architecture/mesh_boundary_decomposition_phase110.md` | Phases 118/119 CLOSED DEFER; Phase 122 mesh-protocol leaf is class 2, not a runtime extraction |
| `architecture/process_sandbox_corrective_closeout.md` | Phase 120 CLOSED RETAIN reconfirmed; native support tiers unchanged |

## 5. DNS next-work pointer (Workstream E)

`architecture/dns_runtime_dto_conversion_research.md` is now linked from
`architecture/dns.md` (module-level status block),
`architecture/overview.md` (Layer 6 DNS row + Documentation Map) and
`architecture/dns_application_neutral_readiness_phase109.md`. Every pointer
states **RESEARCH COMPLETE / IMPLEMENTATION NOT REGISTERED**.

The load-bearing boundary facts recorded in those pointers:

- persisted DNS config stays in `synvoid-config` and remains application-owned;
- the config-to-runtime conversion adapter is composition code under
  `src/server/`;
- `src/dns/` is a guard-enforced pure re-export facade
  (`tests/facade_disposition_guard.rs` lists `dns` in `PURE_FACADES`) and must
  not receive the adapter;
- `synvoid-dns` owns only parsed runtime values; unsupported/deferred persisted
  fields stay fail-closed in `DnsConfig::validate()` and are absent from any
  runtime API.

No DNS source, config or runtime API was touched.

## 6. Agent and skill knowledge (Workstream G)

Actionable guidance only; no campaign history was added to agent files for
completeness.

- `AGENTS.md` — the "Public libraries" index now spans Phases 47/115–124 and
  links the Phase 124 closeout with the branch-head/merge-head distinction; a
  new "DNS boundary research (NOT registered implementation)" index line
  carries the `src/server/` vs `src/dns/` facade rule.
- `crates/synvoid-dns/AGENTS.override.md` — a "Crate boundary status" section
  records class 1, the CLOSED DEFER Phases 116/117, and the research-level
  boundary rules, explicitly not authorizing the work.
- `crates/synvoid-honeypot/AGENTS.override.md` was reviewed and needed no
  change: it makes no class, publication or external-support claim.
- `.opencode/skills/dns_dnssec/SKILL.md` already carries a "changelog, not
  guidance" scope banner and no stale class/standalone claim; no change.

## 7. Stale-status search and classification ledger (Workstream F)

Searches run across `plans/`, `architecture/`, `docs/`, `AGENTS.md` and
`README.md` for `ACTIVE / REGISTERED`, `PLANNED / READY`,
`BLOCKED ON PHASE 116`, `BLOCKED ON PHASE 118`, `post-push check`, `Phase 107`,
`Phase 109`, `Phase 110`, `external_support`, `class 2`, `class 3`. Every hit
is classified below. **Stale = corrected this phase; historical = intentionally
retained; current = already correct.**

| Hit | Location | Classification | Disposition |
|---|---|---|---|
| `post-push check` | `plans/roadmap.md` campaign status | stale | corrected — replaced by the two-proof table |
| `post-push check` | `plans/standalone_crate_generalization_roadmap.md` header | stale | corrected — replaced by both proofs |
| `post-push check` | `plans/phase_124_*.md` (defect description + search list) | historical | retained — it is the plan's own defect description and search term |
| `ACTIVE / REGISTERED` | `plans/roadmap.md` status header and Phase 124 heading | stale | corrected to CLOSED QUALIFIED |
| `ACTIVE / REGISTERED` | `plans/phase_113_*.md` | historical | retained — Phase 113's own historical reconciliation target |
| `PLANNED / READY` | `plans/roadmap.md` Phase 124 section | stale | corrected to CLOSED QUALIFIED |
| `PLANNED / READY` | `plans/standalone_crate_generalization_roadmap.md` Phase 124 block | stale | corrected to CLOSED QUALIFIED |
| `PLANNED / READY` | `plans/phase_124_*.md` header | stale | corrected at closure |
| `PLANNED / READY` | `plans/roadmap.md:1762` (Phase 113 defect text), `plans/phase_106_*.md:263` (Phase 107 registration) | historical | retained — contemporaneous execution text of closed phases |
| `BLOCKED ON PHASE 116` | `plans/phase_124_*.md` search list only | historical | retained — search term, no such sentence exists in current authority |
| `BLOCKED ON PHASE 118` | `plans/phase_118_*.md:186` | historical | retained — contemporaneous Phase 118 execution text; the plan file header now reads CLOSED DEFER and the roadmap/umbrella agree, so no current-authority text claims 119 is merely blocked |
| `Phase 107` | `architecture/overview.md` honeypot row | stale | corrected — Phase 121/123 status now stated |
| `Phase 107` | `architecture/honeypot_standalone_qualification_phase107.md` body | historical | retained intact; supersession note appended |
| `Phase 109` | `architecture/overview.md` DNS row | stale | corrected — Phases 116/117 DEFER now stated |
| `Phase 109` | `architecture/dns_application_neutral_readiness_phase109.md` body | historical | retained intact; supersession note appended |
| `Phase 110` | `architecture/overview.md` mesh row | stale | corrected — Phases 118/119 DEFER reinforced |
| `Phase 110` | `architecture/mesh_boundary_decomposition_phase110.md` body | historical | retained intact; supersession note appended |
| `external_support` | `architecture/public_crate_release_policy.md`, `standalone_crate_contract.md`, Phase 121/122/123 closeouts and plans, `plans/roadmap.md` | current | unchanged — all say `false` for the three class-2 leaves |
| `class 2` / `class 3` | `architecture/public_crate_release_policy.md`, `standalone_crate_phase123_closeout.md`, `architecture/overview.md`, `AGENTS.md`, `docs/releasing.md`, `README.md` | current | unchanged — `synvoid-rate-limit` is the only class-3 crate anywhere |
| `class 2` as a promotion claim | any current-authority doc | none found | no class-2 package is described as class 3 or externally supported |

Additional contradiction found outside the plan's search list: the workspace
member/crate counts inside `architecture/overview.md` contradicted each other
and the manifest (§3.1) — stale, corrected.

## 8. Verification

Documentation/evidence only; the implementation tree is unchanged, so the
`f8118214`/`cacd44bf` evidence was deliberately retained rather than replaced by
a docs-commit SHA. Checks run on this working tree:

| Check | Result |
|---|---|
| `git diff --check` | clean |
| `cargo fmt --all -- --check` | passed (2.4s as part of verify) |
| `cargo test -p synvoid-repo-guards --profile ci` | passed (all suites green) |
| `cargo xtask verify` | **10 steps, 10 passed, 0 failed, 0 skipped** (1002.1s) |

Verify step timings recorded by `cargo xtask verify` on this machine: fmt 2.4s;
clippy `--profile ci --all-targets -D warnings` 306.5s; `cargo deny check`
2.4s; `cargo check --no-default-features --profile ci` 68.3s; repo-guards
nextest 1.6s; `security_regression` single-threaded 382.5s; root guard suite
(23 tests, `--features mesh`) 13.9s; core admin tests 3.8s; admin contract
(`--features mesh,dns,icmp-filter`) 217.4s; failure injection 3.3s.

The markdown-link guard failed once during execution — correctly — because
`architecture/overview.md` linked the closeout file before it existed. The
guard was re-run after the closeout was written and passes.

`cargo xtask verify-full` and `cargo xtask verify-release` were **not** rerun:
they are not required for truthful documentation edits, no repository guard
requires them, and the plan forbids substituting a docs commit for the retained
exact tested SHA. No check is claimed here that did not run.

No `Cargo.toml`, `Cargo.lock`, Rust source, workflow, support tier or package
metadata changed in this phase — confirmed by the changed-file list, which is
documentation and agent-guidance files only.

## 9. Successor-plan determination

**No future plan is unblocked by Phase 124.** Re-checked against the Phase 123
gate and this reconciliation:

| Track | Status after Phase 124 | What would still be required |
|---|---|---|
| DNS 116/117 | CLOSED DEFER (unchanged) | Persisted/runtime DTO split, composition adapter, provider seam and authoritative/resolver/DNSSEC/encrypted-transport parity delivered together. The design blocker is answered in research only. |
| Mesh 118/119 | CLOSED DEFER (unchanged) | A typed async application-capability boundary plus authority, failure, cancellation, framing and differential parity evidence. |
| Sandbox 120 | CLOSED RETAIN in `synvoid-platform` (unchanged) | A concrete dependency-reachability reduction with unchanged guarantee/native conformance evidence. |
| Honeypot 121 | Class 2, `external_support=false` (unchanged) | A macOS runner for native runtime qualification. |
| Keystore 122 | Class 2, `external_support=false` (unchanged) | An actual PKCS#11 module/token for live provider qualification, plus an RSA advisory/exposure decision for promotion. |
| Mesh protocol 122 | Class 2, `external_support=false` (unchanged) | An independent support/repository case. |
| ICMP / YARA / proxy-cache / tarpit / filter / jail-protocol / native-extension | RETAIN / DEFER / internal (unchanged) | Their own second-consumer, native-support or semantic-contract triggers. |

The DNS runtime-DTO research is **recorded, not registered**. No Phase 125
implementation plan exists, and Phase 124 does not imply one. The class-3 bar in
`architecture/public_crate_release_policy.md` is the only route to external
support, and it is unchanged.

## 10. Acceptance and rejection criteria

Acceptance criteria — all met:

- no current-authority roadmap claims campaign CI still awaits post-push proof
  while also citing `f8118214`;
- branch-head versus merge-head evidence is explicit and unmerged;
- the architecture overview reflects Phase 123 terminal crate classifications;
- historical Phase 107/109/110 and process-sandbox records remain
  historically truthful, with pointers rather than rewrites;
- no class-2 package is described as class 3 or externally supported;
- DNS runtime-DTO research is discoverable without being registered as
  implementation;
- no production or dependency file changed.

Rejection criteria — none triggered: no historical evidence was rewritten to
look current, `cacd44bf` exact-SHA CI is claimed only with an observed run
(`37218651222`), documentation cleanup altered no DNS runtime/config API, no
package was promoted or published, no class/support status changed, and no
Phase 125 implementation work was created.
