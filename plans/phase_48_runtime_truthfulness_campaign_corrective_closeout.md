# Phase 48 Plan: Runtime Truthfulness / Security / Publication Campaign Corrective Closeout

Status: implemented and closed; retained as historical corrective handoff detail.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Closeout: `architecture/runtime_truthfulness_security_publication_closeout.md`.

Registered in: `plans/roadmap.md`.

Baseline for this corrective pass: `main` at `91732e22886451bf5c5547ea125d2a38bd58cefd` (2026-09-19).

## Primary goal

Close the Phase 41-47 runtime-truthfulness/security/publication campaign as a coherent historical unit now that the implementation has landed, reconcile stale planning/status text with the actual repository state, verify that the binding architecture documents and guards match the landed behavior, and separate genuinely remaining follow-up work from completed campaign obligations.

This is a corrective closeout pass, not a new architecture campaign.

The default outcome is documentation/status/evidence reconciliation plus verification. Runtime code should not change unless this pass finds a concrete mismatch between a Phase 41-47 acceptance criterion and the landed implementation.

## Why this plan exists

The implementation sequence has completed through Phase 47, but the planning surface still describes the campaign as active:

- `plans/runtime_truthfulness_security_publication_roadmap.md` still says `Status: detailed active handoff roadmap`;
- `plans/roadmap.md` still describes the post-Phase-40 campaign as an active handoff;
- the Phase 41-47 plan files still present themselves as handoff plans rather than completed historical plans;
- current binding architecture and `AGENTS.md` already describe Phases 41-47 as landed;
- Phase 47's eggfetch disposition contains time-sensitive evidence that is already stale: it records eggfetch as still 0.1.4, while the eggfetch repository has moved beyond the 0.1.5+ threshold that Phase 47 itself defined for reopening the comparison.

The repository should not require a future agent to infer campaign status from commit history while the canonical roadmap says the opposite.

## Landed implementation evidence

The corrective pass should verify these commits and treat them as the implementation evidence baseline:

| Phase | Commit | Landed result |
|---|---|---|
| 41 | `a3e5ab27f8ce` | fail-closed capability config preflight, process/supervisor validation, checked derived capacities |
| 42 | `0026e934e49b` | checked mmap layouts, versioned headers, file hardening, narrowed shared-state API |
| 43 | `7b2aff0be715` | bounded bcrypt executor, async auth boundaries, durable/fail-closed auth persistence |
| 44 | `220dd5dea91d` | migration from `pqc_kyber_edit` to maintained final FIPS 203 `ml-kem` |
| 45 | `69a47c68b1b1` | fail-closed DNS config truthfulness, DoQ bind fidelity, bounded persistent authoritative TCP/DoT |
| 46 | `f31e2cb07050` + `471b3b4d596c` | platform sandbox truthfulness, macOS SBPL hardening/native tests, Linux clippy correction |
| 47 | `91732e228864` | public-crate release policy and promotion of exactly `synvoid-rate-limit` to class 3 |

At the Phase 47 baseline, both the push CI run and the subsequent scheduled CI run completed successfully. The Phase 47 commit records `cargo xtask verify` 10/10 and `cargo xtask verify-full` 10/10, including a 7,347-test workspace nextest run plus doctests.

Do not blindly copy those claims into a new closeout report. Re-run the required gates at the closeout head and record fresh evidence.

## Scope

This phase owns:

1. planning/status reconciliation for Phases 41-47;
2. a final acceptance-criterion audit against landed code and binding docs;
3. closeout evidence and guard/doc consistency;
4. removal of stale time-sensitive factual claims that make completed architecture decisions look current when their prerequisite has changed;
5. explicit separation of remaining follow-up work from the completed campaign.

This phase does **not** own:

- a new broad architecture audit;
- another crate split/merge campaign;
- implementation of deferred DNS capabilities;
- implementation of mesh restart;
- publication of additional crates;
- migration from `synvoid-http-client` to eggfetch;
- an eggfetch parity implementation;
- removal of the temporary YARA/minify compatibility forks unless their upstream removal condition independently becomes satisfied during this pass;
- unrelated dependency upgrades.

## Workstream A — Re-audit Phase 41-47 acceptance criteria against current main

For each Phase 41-47 plan:

1. read the original acceptance criteria;
2. map each criterion to the landed implementation, test, guard, or binding document;
3. classify it as:
   - satisfied;
   - satisfied with an intentional narrower decision;
   - explicitly deferred/non-goal;
   - residual requiring corrective work;
4. do not mark the phase complete if a criterion is merely described in a commit message without code/test/document evidence.

At minimum, re-check the following high-value contracts.

### Phase 41

- reduced-feature builds reject `[dns]`, `[mesh]`, `[tunnel.mesh]`, and `[icmp_filter]` when the capability is not compiled;
- the raw-TOML preflight remains the canonical `MainConfig::from_toml_str()` path;
- process/supervisor validation is reachable from `MainConfig::validate()`;
- worker/count/timeouts/address constraints are bounded;
- runtime capacity derivations remain checked;
- unsupported mesh restart activation/tuning fails before runtime construction.

Binding evidence should remain centered on `architecture/config_feature_contract.md`.

### Phase 42

- all shared-memory size/offset arithmetic flows through checked layout types;
- release builds enforce range/alignment preconditions before unsafe references;
- shared mappings have version/magic validation;
- creator/open-existing ownership is explicit;
- file paths reject symlink/non-regular misuse and use restrictive permissions;
- raw mutable mmap escape hatches remain absent;
- cross-process atomic support scope remains documented rather than implied portable.

Binding evidence should remain centered on `architecture/shared_memory_atomic_contract.md`.

### Phase 43

- bcrypt does not execute on Tokio core executor threads;
- CPU-hard operations are admitted through bounded concurrency;
- no auth-store lock is held across bcrypt;
- Basic Auth/admin token request paths preserve async/fail-closed overload semantics;
- auth-store replacement is temp-write + sync + rename rather than in-place overwrite;
- corrupt/over-permissive existing stores fail closed;
- login audit retention is bounded at insertion.

Binding evidence should remain centered on `architecture/auth.md` and `architecture/auth_deep_dive.md`.

### Phase 44

- `pqc_kyber` / `pqc_kyber_edit` are absent from the active dependency graph;
- final ML-KEM compatibility evidence remains explicit rather than inferred from equal wire sizes;
- KAT, round-trip, malformed/implicit-rejection, wasm build, and AWS-LC interoperability evidence remains represented;
- security docs do not describe package renaming as remediation.

Binding evidence should remain centered on `architecture/pqc.md`, `architecture/wasm_pow.md`, and `SECURITY.md`.

### Phase 45

- deferred DNS feature activation is rejected rather than silently accepted;
- admin DNS mutation uses the same validation contract;
- DoQ bind configuration is honored;
- authoritative DNS-over-TCP and DoT persistence remains bounded and sequential;
- persistent-connection limits/timeouts/permit lifetime/graceful drain have direct tests;
- docs/UI/config examples do not advertise deferred capabilities as active.

Binding evidence should remain centered on `architecture/dns_config_runtime_matrix.md` and `architecture/dns.md`.

### Phase 46

- SBPL path literals cannot be syntactically escaped by operator-controlled path contents;
- Basic/Strict profile semantics match their documentation;
- `sandbox_init` error memory is consumed/freed correctly;
- capability reporting does not claim enforcement the backend cannot provide;
- native macOS tests remain the evidence for experimental Seatbelt support;
- docs clearly distinguish deprecated Seatbelt from App Sandbox;
- Linux remains the production strict-isolation target unless evidence deliberately changes that support tier.

Binding evidence should remain centered on `docs/SANDBOXING.md` and `architecture/platform.md`.

### Phase 47

- only crates that actually meet class-3 policy are represented as externally supported;
- `synvoid-rate-limit` retains its declared MSRV, docs, changelog, property tests, and package-outside-workspace evidence;
- no deferred crate gains `rust-version`/support language that accidentally implies a support promise;
- `synvoid-utils` and `synvoid-core` remain internal;
- publication remains manual;
- no stale comparison claim is used to justify the current `synvoid-http-client` disposition.

Binding evidence should remain centered on `architecture/public_crate_release_policy.md` and `architecture/public_crate_release_readiness_phase47.md`.

## Workstream B — Convert planning files from active handoff to historical completion

After Workstream A is clean, reconcile the planning surface.

### `plans/runtime_truthfulness_security_publication_roadmap.md`

Change the roadmap from active handoff to completed historical campaign.

Required additions:

- final implementation range/baseline;
- concise Phase 41-47 outcome table;
- pointer to the Phase 48 closeout report;
- explicit list of intentional residuals that are **not** campaign failures;
- statement that future work must open a new plan rather than silently extending this campaign.

Do not erase the original findings, dependency ordering, or non-goals. They are useful historical rationale.

### Phase 41-47 plan files

Change each top-level status from handoff/active wording to a completed historical status, for example:

`Status: implemented and closed; retained as historical handoff detail.`

Add a small closeout header or footer with:

- implementation commit(s);
- binding architecture document(s);
- Phase 48 closeout report pointer.

Do not rewrite the original plan body into a retrospective. Preserve the implementation intent so future regressions can be compared with the original acceptance criteria.

### `plans/roadmap.md`

Replace the active post-Phase-40 section with a completed campaign summary and register Phase 48 as the final corrective closeout while it is in progress.

When Phase 48 itself closes, the top-level roadmap should have no active handoff solely because these historical plans exist.

## Workstream C — Create one canonical closeout report

Create:

`architecture/runtime_truthfulness_security_publication_closeout.md`

This should be the final evidence document for the campaign rather than scattering completion prose across seven plans.

Required structure:

1. baseline and final commit;
2. Phase 41-47 result table;
3. acceptance-criterion audit summary;
4. verification commands and results;
5. deliberate residuals/follow-ups;
6. public support boundary after Phase 47;
7. security/supply-chain residuals that remain intentionally open;
8. references to binding architecture docs.

The report must distinguish:

- **closed defect**;
- **truthfully unsupported capability**;
- **accepted dependency/supply-chain residual**;
- **new follow-up opened after the campaign**.

Do not call a truthfully rejected DNS feature "implemented", and do not call a low-exposure advisory "patched".

## Workstream D — Remove stale eggfetch-version evidence without making a migration decision

Phase 47 deliberately deferred a public `synvoid-http-client` support decision until eggfetch 0.1.5+ could be evaluated. That threshold has now been crossed outside SynVoid.

Current stale claims include wording equivalent to:

- "eggfetch still 0.1.4";
- "no 0.1.5+ line exists";
- Phase 34's matrix therefore still being current evidence.

Those statements must not survive Phase 48 as present-tense facts.

Required corrective action:

1. update `architecture/public_crate_release_readiness_phase47.md`, `AGENTS.md`, and any other current-state docs so they say:
   - the Phase 47 decision was made against the then-current eggfetch baseline;
   - a newer eggfetch line now exists;
   - `synvoid-http-client` remains internal pending a fresh parity/consolidation review;
   - the old matrix must not be used as current evidence;
2. keep the historical Phase 47 decision itself intact;
3. do **not** adopt eggfetch or remove `synvoid-http-client` in this phase;
4. register a separate focused follow-up plan if one does not already exist for the current eggfetch line.

The follow-up must evaluate at least:

- TLS backend/provider parity, including SynVoid's aws-lc/PQ requirements;
- HTTP/1.1 and HTTP/2 behavior used by SynVoid;
- streaming/open request-body requirements;
- direct Unix-domain-socket routing;
- connection pooling and resolved-target reuse;
- timeout semantics across headers/body/redirects/retries;
- certificate-chain versus hostname-verification control;
- size/error/response-body limits;
- dependency footprint and duplicate Hyper/Rustls stack impact;
- API maturity/MSRV/support burden;
- whether SynVoid can become a thin adapter instead of owning a second generic client.

This is a follow-up decision gate, not a Phase 48 implementation task.

## Workstream E — Reconcile current-state knowledge surfaces

Audit at least:

- `AGENTS.md`;
- `README.md`;
- `SECURITY.md`;
- `docs/FEATURE_STATUS.md`;
- `docs/releasing.md`;
- `architecture/overview.md`;
- `architecture/agent_knowledge_maintenance.md`;
- relevant `.opencode/skills/*/SKILL.md` files touched by Phases 41-47.

Rules:

- binding architecture docs own current semantics;
- plans own historical implementation intent;
- operator docs describe supported behavior;
- `AGENTS.md` may summarize known issues but should not duplicate stale version-sensitive research as permanent truth;
- time-sensitive dependency/version comparisons should point to a dated decision record rather than masquerading as timeless architecture.

If multiple current-state documents repeat the same detailed version-sensitive claim, reduce the duplication and point to the canonical evidence record.

## Workstream F — Guard against campaign-status drift

Add a narrow repo guard only if the repository currently has no equivalent protection.

Useful assertions may include:

- the umbrella Phase 41-47 roadmap is not marked active after closeout;
- no Phase 41-47 plan is marked as an active handoff;
- `plans/roadmap.md` agrees with the umbrella roadmap;
- only the public crates listed by `architecture/public_crate_release_policy.md` are represented as externally supported;
- current-state docs do not contain the known stale literal `eggfetch still 0.1.4`.

Do not create a brittle guard that bans ordinary historical text under `plans/`. Historical records are allowed to say what was true at the time; the guard should target current-state/status surfaces.

## Workstream G — Verification

Minimum focused verification:

```bash
cargo fmt --all -- --check
cargo xtask test guards
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-upstream --profile ci
cargo test -p synvoid-auth --profile ci
cargo test -p synvoid-wasm-pow --profile ci
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-platform --profile ci
cargo test -p synvoid-rate-limit --profile ci
cargo test -p synvoid-rate-limit --doc --profile ci
```

Repository gates:

```bash
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Run `cargo xtask verify-release` when the tree is clean and the environment satisfies its release prerequisites. It must remain a dry-run/qualification surface and must never publish automatically.

If Phase 48 makes documentation/status-only changes and the focused tests are unchanged from the exact same code head, the closeout report may cite the immediately preceding green implementation evidence **only in addition to**, not instead of, the current repository guard/verification run.

## Acceptance criteria

Phase 48 is complete only when all of the following are true:

- Phases 41-47 have been re-audited against their original acceptance criteria;
- no unresolved criterion is hidden behind a "complete" label;
- `plans/runtime_truthfulness_security_publication_roadmap.md` is explicitly completed/historical;
- all Phase 41-47 plan statuses reflect implemented historical state;
- `plans/roadmap.md` no longer calls the Phase 41-47 implementation campaign active;
- `architecture/runtime_truthfulness_security_publication_closeout.md` exists and records the final evidence;
- current-state docs agree on the support/security/runtime contracts established in Phases 41-47;
- stale eggfetch 0.1.4/no-0.1.5+ claims are removed from current-state documentation;
- `synvoid-http-client` remains internal until a separate current-line eggfetch review is completed;
- deferred DNS features remain truthfully rejected rather than being relabeled complete;
- macOS Seatbelt remains experimental/deprecated unless new native evidence explicitly changes the support tier;
- only `synvoid-rate-limit` is class 3 unless an entirely separate publication qualification promotes another crate;
- YARA/minify compatibility forks and remaining advisories are described accurately rather than silently folded into campaign completion;
- verification and dependency-security gates are green at the closeout head, or any environment-specific inability is explicitly recorded without claiming success.

## Rejection criteria

Reject the closeout if it:

- changes runtime semantics merely to make a plan checkbox pass;
- converts unsupported DNS features into silent no-ops;
- adopts eggfetch without the dedicated parity/consolidation review;
- publishes another crate as part of closeout bookkeeping;
- rewrites historical plans so heavily that original intent is lost;
- deletes security residuals from docs because they are outside this campaign;
- treats passing `cargo audit` as proof that all cryptographic provenance concerns are solved;
- calls deprecated macOS Seatbelt equivalent to App Sandbox;
- reports old CI or commit-message claims as fresh verification without re-running the appropriate current-head gates;
- leaves the canonical roadmap, binding docs, and `AGENTS.md` disagreeing about whether the campaign is active.

## Expected file classes

Likely modified:

- `plans/runtime_truthfulness_security_publication_roadmap.md`;
- `plans/phase_41_fail_closed_config_and_process_bounds.md`;
- `plans/phase_42_shared_memory_unsafe_boundary_hardening.md`;
- `plans/phase_43_auth_cpu_and_persistence_hardening.md`;
- `plans/phase_44_pqc_dependency_truth_and_kyberslash_closure.md`;
- `plans/phase_45_dns_runtime_contract_and_protocol_completeness.md`;
- `plans/phase_46_platform_sandbox_truthfulness_and_macos_closure.md`;
- `plans/phase_47_public_crate_release_readiness.md`;
- `plans/roadmap.md`;
- `architecture/runtime_truthfulness_security_publication_closeout.md`;
- `architecture/public_crate_release_readiness_phase47.md`;
- `architecture/overview.md`;
- `architecture/agent_knowledge_maintenance.md`;
- `AGENTS.md`;
- selected operator/security/release docs if the audit finds stale claims;
- a narrow repo-guard test if needed.

Not expected:

- production runtime implementation changes;
- dependency migrations;
- new public crates;
- DNS feature implementation;
- HTTP-client replacement.

## Handoff sequence

1. Audit the seven phase acceptance criteria against `main`.
2. Fix any true mismatch before changing status labels.
3. Create the canonical architecture closeout report.
4. Reconcile Phase 41-47 and umbrella-plan statuses.
5. Correct stale current-state eggfetch evidence and separate the follow-up decision gate.
6. Reconcile knowledge/operator/security docs.
7. Add only narrowly justified status/current-state guards.
8. Run focused and repository-wide verification.
9. Record final commit/evidence in the closeout report.
10. Mark Phase 48 and the post-Phase-40 campaign complete in `plans/roadmap.md`.

After Step 10, there should be no active handoff under this campaign. Any DNS expansion, public-crate promotion, dependency-fork removal, or eggfetch consolidation must be represented by a new focused plan with its own baseline and acceptance criteria.
