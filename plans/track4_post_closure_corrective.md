# Track 4 Post-Closure Corrective Plan

Status: complete (2026-09-13). Implementation commit: `236c71e1`. Closure evidence: `architecture/track4_post_closure_corrective_report.md` (verify-release 14/14 on the clean implementation tree; closure commit records the result).

The body below is the executed handoff specification, preserved as historical implementation guidance.

Scope: narrow truthfulness, verification, and trust-path corrective pass after Track 4 (Phases 25-31) landed successfully on `main` through `688fa74ee764f1b0efbd2d109814f93c418b99cb` and the canonical GitHub Actions run for that SHA completed successfully (`CI` run 911; both `ci` and `dependency-security` jobs green).

Primary goal: close the remaining post-Track-4 evidence and hardening residuals without reopening the crate architecture, weakening the completed capability boundaries, or starting another broad refactor.

The Track 4 implementation itself remains complete. This plan exists because the final review found four closure-quality residuals: historical plan/status metadata is stale, advisory review deadlines are not truly time-aware, the final changed parser boundaries lack recorded bounded fuzz smoke on the final tree, and the supervisor-to-YARA validation path needs an explicit trust/reachability decision.

## Baseline and completed work that must not be reopened

The following Phase 25-31 landing sequence is the baseline for this pass:

- Phase 25 — dependency security baseline and entitlement closure: `4d5cb580639c3c7bde8494ac3fbd551e568d22f9`
- Phase 26 — YARA execution boundary consolidation: `390af6abd76a7cd5945a560823f9e23bdd667f7b`
- Phase 27 — mesh protocol contract extraction: `ac3b8e8732e6ebbba478e1daaded8f5728d10506`
- Phase 28 — native extension capability isolation: `d3ad2bc2e81486604b09a3d1e553d6b11944a5de`
- Phase 29 — jail runtime package/process split: `fd10114507767b41eb40891d0b917e95dd206419`
- Phase 30 — DNSSEC key-custody boundary extraction: `6351b39d442ee4295b4a24ae23d0c4b43304c92c`
- Phase 31 — dependency-surface closeout and release verification: `688fa74ee764f1b0efbd2d109814f93c418b99cb`

The final Track 4 architecture evidence remains `architecture/track4_dependency_security_closeout.md`. The corrective implementation must amend current-state evidence where needed; it must not rewrite the historical intent of the executed Phase 25-31 plan bodies.

## Why this corrective pass exists

The final review found that the architecture and implementation landed correctly, but closure metadata and a few verification properties do not yet meet the same standard:

1. The individual Phase 25-31 plan files still present themselves as pending (`ready for implementation` / `implement after ...`) even though every phase has landed and the Track 4 roadmap is marked complete.
2. `SECURITY.md`, release guidance, baseline evidence, and `deny.toml` still contain milestone-based advisory language such as `Remove-by: Phase 26` or `Phase 27` even though those phases are complete. Some dependency descriptions also describe pre-Phase-31 root ownership (for example stale bincode/root wording).
3. `tools/synvoid-repo-guards/tests/dependency_security.rs` uses a fixed `REVIEW_HORIZON = "2026-09-12"`. A future `2026-10-01` re-audit deadline therefore does not become failing merely because calendar time advances; a maintainer must manually move the horizon first.
4. Phase 31 correctly identified the relevant fuzz targets but did not record a bounded smoke run on the final Track 4 parser/protocol tree.
5. `src/supervisor/mesh.rs` injects a `YaraSyntaxValidator` that calls `synvoid_yara::validate_rules_syntax()` in process. `synvoid-mesh` itself no longer links `yara-x`, which is correct, but the trust ordering for every rule-text ingress needs to be proven: untrusted network/peer rule text must not reach the full YARA parser/compiler in the supervisor before the intended size, provenance, signature, role, and approval gates.

These are closure/hardening residuals, not evidence that the Track 4 crate boundaries should be redesigned.

## Non-goals

- Do not create another architecture track solely for this corrective work.
- Do not add `synvoid-admin-server`, `synvoid-waf-runtime`, or `synvoid-sdk`.
- Do not split or merge crates merely to change crate count.
- Do not move YARA compilation back into `synvoid-mesh` or `synvoid-upload`.
- Do not weaken the dedicated jail process boundary, native-extension compile gate, mesh-protocol dependency budget, DNSSEC key-custody boundary, or root dependency entitlement guard.
- Do not upgrade Wasmtime/YARA by forcing incompatible dependency versions. If the upstream blocker has disappeared by implementation time, a normal dependency update may be handled as a separately justified fix, but this plan is not an excuse to bypass compatibility testing.
- Do not rewrite historical plan bodies into result reports. Update their status/closure preambles only, preserving the executed handoff specification beneath them.
- Do not add a permanent CI fuzz matrix. This pass needs bounded evidence, not a new high-cost routine workflow.
- Do not assume the supervisor YARA validator is unsafe merely because it is in process; prove ingress ordering and capability reachability first.

## Workstream A — Reconcile Track 4 plan and security documentation truth

### A1. Mark the executed Phase 25-31 plans complete

Update only the status/closure preamble of:

- `plans/phase_25_dependency_security_baseline_and_entitlement.md`
- `plans/phase_26_yara_execution_boundary_consolidation.md`
- `plans/phase_27_mesh_protocol_contract_extraction.md`
- `plans/phase_28_native_extension_capability_isolation.md`
- `plans/phase_29_jail_runtime_package_and_process_split.md`
- `plans/phase_30_dnssec_keystore_boundary_extraction.md`
- `plans/phase_31_dependency_surface_closeout_and_release_verification.md`

Use the repository's established post-closure convention:

```text
Status: complete (2026-09-12). Landing commit: `<sha>`. Closure evidence: `architecture/track4_dependency_security_closeout.md`.

The body below is the executed handoff specification, preserved as historical implementation guidance.
```

For Phase 31, identify it explicitly as the final Track 4 closeout. Do not rewrite acceptance/rejection criteria or command lists to match hindsight; those are historical specifications.

Add a small guard or truthfulness assertion if the repository already has a suitable plan-status validation seam. Do not introduce a new parser/framework solely to lint Markdown statuses.

### A2. Normalize advisory ownership/review metadata to current state

Audit current, non-historical dependency-security guidance at minimum:

- `SECURITY.md`
- `deny.toml`
- `.cargo/audit.toml`
- `architecture/dependency_security_baseline_phase25.md`
- `architecture/track4_dependency_security_closeout.md`
- `docs/RELEASE.md`
- `docs/releasing.md`
- `docs/testing/verification-contract.md`
- `AGENTS.md`

Required corrections:

1. Replace already-expired milestone labels such as `Remove-by: Phase 26` / `Phase 27` with the actual unresolved condition plus a real calendar re-audit date.
2. Standardize advisory metadata to distinguish:
   - `Reviewed: YYYY-MM-DD` — historical last review date;
   - `Re-audit: YYYY-MM-DD` — machine-enforced future deadline;
   - `Remove condition: ...` — upstream/event condition, not a date.
3. Keep `RUSTSEC-2026-0269` wording exact: Wasmtime 42.0.2 and 40.0.4 are version-affected; `wasmtime-wasi` is absent from the resolved lock/graph; the current decision is capability absence plus an upgrade blocker, not "patched".
4. Recompute and correct statements about direct/root dependency ownership. Do not keep statements such as "bincode is a direct root dependency" if `cargo metadata` / the current root manifest no longer support them.
5. Keep `.cargo/audit.toml` and `deny.toml` advisory sets synchronized.
6. If an ignore's upstream blocker has actually cleared by implementation time, resolve or update the dependency instead of automatically extending its exception.

Recommended searches:

```bash
rg -n "Remove-by: Phase|remove-by Phase|Phase 26|Phase 27" \
  SECURITY.md deny.toml .cargo/audit.toml architecture docs AGENTS.md
rg -n "bincode.*root|root.*bincode|direct root rsa|direct root" \
  SECURITY.md architecture docs AGENTS.md deny.toml
rg -n "42\.0\.2.*patched.*0269|0269.*patched" . --glob '!target/**'
```

Historical Phase 25 plan text may retain its original milestone language after its completion preamble is added; current policy documents may not.

### A3. Create a compact corrective closure report

When implementation is complete, create:

`architecture/track4_post_closure_corrective_report.md`

It should record only current reproducible evidence:

- corrective base SHA and final SHA;
- final Phase 25-31 plan-status reconciliation;
- advisory metadata/re-audit state;
- effective-date guard implementation and tests;
- bounded fuzz commands/results/tool versions;
- mesh-to-YARA ingress/trust-path table and final disposition;
- canonical `cargo xtask verify` result;
- any broader verification rerun required by code changes;
- remaining accepted upstream blockers with next re-audit dates.

Do not duplicate the full Phase 31 closeout report.

## Workstream B — Make advisory deadlines actually expire

The current guard in `tools/synvoid-repo-guards/tests/dependency_security.rs` compares deadlines against a source constant fixed at the Phase 25/31 review date. Replace that mechanism with an effective current UTC date while preserving deterministic unit-testability.

### B1. Define one machine-readable deadline contract

After Workstream A, every ignored advisory in `deny.toml` must have exactly one future calendar deadline in a normalized comment field:

```text
# Re-audit: 2026-10-01.
```

`Reviewed:` is informational and may be in the past. `Remove condition:` may be an upstream event and is not parsed as a deadline.

The guard should reject:

- missing `Owner:`;
- missing `Re-audit: YYYY-MM-DD`;
- malformed dates;
- `Re-audit` dates on or before the effective current date;
- duplicate/conflicting re-audit dates for one advisory metadata block;
- an advisory in `.cargo/audit.toml` not represented in `deny.toml` or vice versa.

### B2. Use real UTC time without making tests flaky

Preferred design:

1. Extract pure helpers for parsing `YYYY-MM-DD`, comparing calendar dates, and evaluating one metadata block against an explicit `as_of` date.
2. The production guard obtains `as_of` from current UTC date.
3. Support an explicit environment override such as `SYNVOID_SECURITY_REVIEW_AS_OF=YYYY-MM-DD` for deterministic specialist/release tests if needed.
4. Unit-test the pure helper with dates before, on, and after a deadline.
5. Test malformed override/deadline behavior fails closed.

Do not shell out to `date`. Reuse an already-present lightweight date library in the repo-guard tool if appropriate; otherwise add the smallest tool-only dependency justified for correct UTC civil-date conversion. Avoid hand-written calendar conversion unless it is separately tested for leap years/year boundaries.

The ordinary `cargo xtask verify` path must execute this guard so an expired advisory starts failing without a source edit.

### B3. Preserve reproducibility semantics correctly

This check is intentionally time-sensitive: dependency risk acceptance expires with time. That is not the same as making compilation non-reproducible.

If `SOURCE_DATE_EPOCH` is set for package/release reproducibility, do not silently use an old source epoch to bypass an advisory deadline. Security review time should be current UTC or an explicit security-review override.

Update `docs/testing/verification-contract.md` to make this distinction clear.

## Workstream C — Record bounded Track 4 fuzz evidence

Track 4 changed protocol/jail/plugin trust boundaries. Run bounded fuzz smoke against the final corrective tree using the repository's existing 1000-run closure convention.

Required existing targets:

```bash
cargo +nightly fuzz run jail_ipc_frame_decode -- -runs=1000
cargo +nightly fuzz run mesh_protocol_compressed_decode -- -runs=1000
cargo +nightly fuzz run plugin_manifest -- -runs=1000
```

Rationale:

- `jail_ipc_frame_decode` covers the Phase 29 versioned child-process wire boundary;
- `mesh_protocol_compressed_decode` covers the Phase 27 extracted mesh protocol/wire surface;
- `plugin_manifest` covers the plugin capability/trust metadata surface adjacent to Phase 28 isolation.

If repository inspection shows one of these targets no longer exercises the production seam named above, repair the target first or document why a different existing target is the production-equivalent one. Do not count a stale harness as evidence.

For each target record:

- exact command;
- final commit SHA;
- nightly rustc version;
- cargo-fuzz/libFuzzer version if available;
- execution count;
- pass/crash/hang result;
- minimized artifact path if a crash occurs.

Crash handling:

1. minimize the input;
2. reproduce outside the fuzzer where practical;
3. add a deterministic regression test in the owning crate/protocol suite;
4. fix the defect;
5. re-run the affected fuzz target for 1000 executions;
6. rerun canonical verification after the fix.

Do not add these smoke runs to every PR unless implementation discovers that the current fuzz policy is insufficient. Record them in `architecture/track4_post_closure_corrective_report.md` and amend the Phase 31 closeout fuzz row to point to that report.

## Workstream D — Resolve the mesh-to-YARA validation trust path with evidence

This workstream is a trust-order audit first and a code change only if the audit proves one is required.

Current relevant shape:

- `synvoid-mesh` owns distribution/approval state and a narrow `YaraSyntaxValidator` trait.
- `synvoid-mesh` itself does not link `yara-x`.
- `src/supervisor/mesh.rs` injects a validator whose `validate()` calls `synvoid_yara::validate_rules_syntax()` in the supervisor process.
- Phase 29 provides a dedicated YARA jail capable of bounded out-of-process YARA execution.

The unresolved question is whether peer/network-controlled rule source can reach the injected full YARA parser/compiler before all intended trust and resource gates.

### D1. Build an ingress/trust-order table

Enumerate every route by which YARA rule text reaches `YaraRulesManager`, including at minimum:

- local/operator direct apply;
- edge-node local submission;
- inbound `MeshMessage::YaraRuleSubmission`;
- global approval/rejection path;
- DHT rule synchronization, including chunked paths;
- feed-manager rule application;
- persisted rules reloaded from disk;
- admin/config paths if they reach mesh rule management.

For each ingress record, in exact order:

1. source/trust domain;
2. maximum byte/rule-count/decompression bounds;
3. cryptographic signature verification and which identity/key is verified;
4. timestamp/replay checks;
5. node-role/authorization check;
6. approval-state gate;
7. structural YARA checks;
8. full `synvoid-yara` syntax/compiler invocation, if any;
9. persistence/broadcast/apply effects.

Do not infer ordering from comments. Follow the actual call graph and add tests that prove the critical order.

### D2. Decision rule

Use the completed ingress table to choose exactly one of these outcomes.

#### Outcome 1 — Retain direct supervisor validation

This is acceptable only if every path that can invoke the injected full validator has already reduced the input to an appropriately trusted/bounded domain before compiler entry. At minimum:

- remote inputs are size/decompression bounded;
- required signatures/provenance are verified before compiler entry;
- role/approval policy has run before compiler entry where policy requires it;
- no unauthenticated peer can use the supervisor as an arbitrary YARA compiler oracle/DoS surface;
- the code path is regression-tested and documented.

If this is proven, keep the direct validator, add an architecture note explaining why it is a deliberate composition-root capability, and add a guard/test that prevents future reordering across the trust boundary.

#### Outcome 2 — Route untrusted full validation through the YARA jail

If any peer/network-controlled text reaches the full parser/compiler before sufficient trust/resource gates, move that full-validation operation behind the existing YARA jail.

Requirements if this outcome is selected:

- reuse the existing versioned `synvoid-ipc` jail protocol or add one narrowly scoped YARA validation operation; do not create generic remote execution;
- preserve digest verification, maximum payload/ruleset limits, deadlines, quarantine/restart semantics, and `IsolationPolicy::Required` fail-closed behavior;
- avoid blocking a Tokio worker on an unbounded synchronous child call; use the existing bounded jail-call model or introduce the smallest async adaptation necessary at the composition boundary;
- keep cheap structural validation inline in `synvoid-mesh` so obvious oversized/malformed submissions are rejected before IPC;
- keep `yara-x` ownership solely in `synvoid-yara` / YARA jail execution packages; `synvoid-mesh` must remain compiler-free;
- distinguish validation failure from jail unavailable/timeout/protocol failure in logs/metrics and policy behavior;
- add integration tests for malformed rule text, timeout/jail failure, required isolation, and successful validation.

### D3. Required regression tests regardless of outcome

Add tests proving at least:

- oversized rule source is rejected before full YARA compilation;
- unauthorized node roles cannot trigger approval-time compiler execution;
- signature/provenance rejection occurs before full compilation on relevant remote paths;
- a rejected or expired submission cannot be promoted by invoking validation directly;
- valid approved rules still propagate and reach the canonical execution boundary;
- `crates/synvoid-mesh/Cargo.toml` still has no direct `yara-x` or Wasmtime execution dependency;
- existing `yara_execution_boundary` guards remain green.

If the current design lacks enough injection points to assert call order, introduce a test-only counting validator/observer rather than weakening encapsulation.

### D4. Documentation

Update as applicable:

- `architecture/mesh.md`
- `architecture/mesh_trust_domains.md`
- `architecture/upload.md`
- `architecture/sandbox_jail_protocol.md`
- `architecture/track4_dependency_security_closeout.md`
- `.opencode/skills/synvoid_mesh/SKILL.md`
- `.opencode/skills/sandboxing/SKILL.md`
- `AGENTS.md`

The final docs must state whether full YARA syntax validation is intentionally in-process after trust admission or out-of-process through the jail, and why.

## Workstream E — Final verification and closure evidence

After Workstreams A-D, run verification proportional to the actual code touched.

Always run:

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo deny check
cargo audit
```

If Workstream B changes repo-guard dependencies/verification machinery, also run:

```bash
cargo nextest run -p synvoid-repo-guards
cargo xtask verify-full
```

If Workstream D changes runtime YARA/jail/mesh behavior, also run at minimum:

```bash
cargo nextest run -p synvoid-mesh
cargo nextest run -p synvoid-yara
cargo nextest run -p synvoid-jail-runtime
cargo nextest run --workspace --exclude synvoid-fuzz
cargo xtask verify-full
cargo xtask verify-release
```

Use a clean tree for the final `verify-release` qualification if runtime/release code changed.

Re-run the three bounded fuzz targets after any code change affecting their production seam.

### Final truthfulness searches

```bash
rg -n "Status: ready for implementation|implement after Phase" \
  plans/phase_2[5-9]* plans/phase_3[01]*
rg -n "Remove-by: Phase|remove-by Phase" \
  SECURITY.md deny.toml .cargo/audit.toml architecture docs AGENTS.md
rg -n "REVIEW_HORIZON|2026-09-12" tools/synvoid-repo-guards/tests/dependency_security.rs
rg -n "42\.0\.2.*patched.*0269|0269.*patched" . --glob '!target/**'
rg -n "synvoid_yara::validate_rules_syntax|set_syntax_validator" \
  src crates/synvoid-mesh architecture
```

Every remaining result must be intentionally historical, a current documented implementation decision, or an explicitly accepted residual in the corrective report.

## Expected files to change

Likely documentation/status changes:

- `plans/phase_25_dependency_security_baseline_and_entitlement.md`
- `plans/phase_26_yara_execution_boundary_consolidation.md`
- `plans/phase_27_mesh_protocol_contract_extraction.md`
- `plans/phase_28_native_extension_capability_isolation.md`
- `plans/phase_29_jail_runtime_package_and_process_split.md`
- `plans/phase_30_dnssec_keystore_boundary_extraction.md`
- `plans/phase_31_dependency_surface_closeout_and_release_verification.md`
- `plans/track4_dependency_security_capability_segregation_roadmap.md`
- `SECURITY.md`
- `deny.toml`
- `.cargo/audit.toml`
- `architecture/dependency_security_baseline_phase25.md`
- `architecture/track4_dependency_security_closeout.md`
- `architecture/track4_post_closure_corrective_report.md` (new)
- `docs/RELEASE.md`
- `docs/testing/verification-contract.md`

Required guard change:

- `tools/synvoid-repo-guards/tests/dependency_security.rs`
- possibly `tools/synvoid-repo-guards/Cargo.toml` only if a small date dependency is required.

Conditional Workstream D code changes only if the trust-order audit proves them necessary:

- `src/supervisor/mesh.rs`
- `crates/synvoid-mesh/src/mesh/yara_rules.rs`
- `crates/synvoid-mesh/tests/yara_approval_boundary.rs`
- `crates/synvoid-ipc/*` only if a new narrow validation operation is required
- `crates/synvoid-jail-runtime/src/yara_service.rs`
- relevant boundary/integration guards/tests.

Do not touch unrelated domain crates.

## Acceptance criteria

This corrective pass is complete only when all of the following are true:

1. Phase 25-31 plan preambles accurately say complete, include their landing SHAs, and preserve the historical plan bodies.
2. Current security/release docs contain no already-completed `Remove-by: Phase 26/27` promises presented as future actions.
3. Every ignored advisory has current owner/exposure evidence, a machine-readable future `Re-audit: YYYY-MM-DD`, and an explicit remove condition where applicable.
4. `cargo audit` and `cargo deny check` use the same intentional advisory exception set.
5. Advisory re-audit deadlines fail automatically when actual UTC time reaches them; no source-constant bump is required to make an exception expire.
6. The date guard is deterministic under an explicit test override and has before/on/after deadline tests.
7. `jail_ipc_frame_decode`, `mesh_protocol_compressed_decode`, and `plugin_manifest` complete 1000-run bounded smokes on the final corrective tree, or any discovered crash is fixed and the target rerun before closure.
8. The mesh/YARA ingress table proves exactly where full syntax/compiler validation occurs relative to bounds, signatures, roles, replay controls, and approval.
9. If remote/untrusted text reached full compilation too early, production validation is moved through the bounded YARA jail and fails closed according to isolation policy.
10. If direct validation is retained, tests and architecture evidence prove it executes only after the required trust/resource gates and cannot be used as an unauthenticated compiler surface.
11. `synvoid-mesh` remains free of direct `yara-x`/Wasmtime execution dependencies.
12. `cargo xtask verify`, `cargo deny check`, and `cargo audit` are green on the final corrective revision; `verify-full`/`verify-release` are green whenever runtime/release behavior changed.
13. `architecture/track4_post_closure_corrective_report.md` records the final SHA, exact evidence, and any remaining upstream blockers.
14. Track 4's completed capability boundaries remain intact; the pass does not re-open rejected count-only crate extractions.

## Rejection criteria

Reject the corrective implementation if it:

- marks the historical plans complete by rewriting their bodies to describe the result rather than preserving the executed specification;
- merely changes `REVIEW_HORIZON` from one hard-coded date to a later hard-coded date;
- treats `Reviewed:` as a future expiry date or permits ignores without a machine-readable `Re-audit:` date;
- suppresses a newly current RustSec advisory by broadening ignores instead of triaging it;
- calls Wasmtime 42.0.2 patched for RUSTSEC-2026-0269;
- records fuzz targets as covered without executing bounded runs against the final corrective tree;
- routes all YARA validation through a new generic IPC/exec API instead of the existing narrow jail model;
- moves `yara-x` back into `synvoid-mesh` for convenience;
- assumes all mesh rule text is trusted without enumerating the ingress/order path;
- weakens signature, role, approval, replay, payload, timeout, or jail fail-closed policy to avoid changing an awkward call path;
- creates new crates or CI matrices that do not remove a concrete capability/risk;
- marks the pass complete while canonical verification is failing or while the corrective report omits an unresolved item.

## Handoff order

Execute serially unless a discovered security defect requires immediate correction:

1. Workstream A — establish truthful plan/security metadata and normalize advisory fields.
2. Workstream B — make the normalized `Re-audit` deadline mechanically time-aware; run repo guards and canonical verify.
3. Workstream D1 — map the mesh/YARA ingress and trust order before changing runtime behavior.
4. Workstream D2-D4 — retain/directly document the current validator if proven safe, or route the affected untrusted path through the YARA jail if not.
5. Workstream C — run bounded fuzz evidence on the resulting final runtime tree; fix/regression-test any crash.
6. Workstream E — run proportional full/release verification, truthfulness searches, and create the corrective closure report.
7. Update this plan to `Status: complete`, include the final corrective SHA/report, and leave the body below as historical handoff guidance.

If the trust-path audit discovers a materially broader execution-authority flaw than described here, stop expanding this plan ad hoc. Fix any immediate unsafe path, record the finding, and create a separately scoped architecture/security plan for genuinely new work.