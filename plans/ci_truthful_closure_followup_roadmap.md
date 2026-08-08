# CI Truthful Closure Follow-up Roadmap

**Status:** PLANNED  
**Created:** 2026-08-08  
**Baseline reviewed:** `584e6fa05b5e570a13140105ca85fb237dc65468`  
**Purpose:** Close the remaining correctness and evidence gaps in the CI verification/release simplification line without re-expanding CI or introducing release automation.

## 1. Why this follow-up exists

The previous truthful-closure implementation materially improved the repository:

- routine GitHub CI remains a single Ubuntu job invoking `cargo xtask verify`;
- product, test, and harness fixes resolved the large majority of the prior `verify-full` failures;
- release verification now has clean-tree enforcement, semver checks, package-content inspection, and explicit manual publication order;
- hosted routine CI has a successful proof run;
- branch-protection uncertainty is now described as external rather than inferred.

However, the line should not yet be considered closed. Three narrow gaps remain:

1. **Release qualification semantics are internally inconsistent.** `verify-release` skips package assembly and packaged-source checks for publishable crates with path dependencies, while the closure contract says every publishable crate must assemble and the summary can still read as though all crates qualified.
2. **Malformed/overlong UTF-8 XSS handling lacks a complete safety contract.** One corpus expectation currently documents a known non-detection path without proving that malformed input is rejected or otherwise rendered non-exploitable by the real HTTP/WAF boundary.
3. **Current evidence and documentation disagree with implementation and with each other.** The closure result carries a stale final SHA, timing wording is inconsistent, the failure ledger mixes intermediate and final states, and the verification contract still contains stale release-command descriptions.

This roadmap closes only those gaps.

## 2. Scope constraints

The implementation must preserve the intentionally simplified operating model.

### Must remain true

- one routine GitHub Actions workflow/job for normal CI;
- Ubuntu-only routine CI unless an unrelated roadmap explicitly changes that policy;
- `cargo xtask verify` remains the only routine hosted verification entry point;
- crates.io publication remains operator-driven and manual;
- no xtask command may publish, tag, create a GitHub release, upload release artifacts, or consume registry credentials;
- no affected-package selector, generated lane manifest, dynamic test scheduler, evidence database, local registry emulator, service container, or release matrix is introduced;
- no product behavior is changed merely to make a verifier green;
- specialist fuzz/Miri/stress/platform checks remain explicit manual tools unless separately planned.

### Explicitly out of scope

- redesigning the WAF architecture beyond the malformed-input contract needed here;
- adding broad new attack classes or a new parsing framework;
- automating sequential crates.io publication;
- making all internal crates independently registry-resolvable before their predecessors exist;
- rebuilding the old multi-lane CI architecture;
- chasing additional routine-CI optimization unless fresh evidence crosses the existing blocking threshold.

## 3. Phase structure

### Phase 1 — Release Qualification Semantics

Plan: `plans/ci_truthful_closure_followup_phase_01_release_qualification.md`

Goal: make `verify-release` report package qualification truthfully and enforce the exact level of proof possible before manual publication.

Primary outputs:

- explicit per-crate qualification states;
- no path-dependent crate silently counted as assembled/verified;
- package assembly attempted wherever Cargo can actually perform it;
- unresolved predecessor dependencies named explicitly;
- topological publication ordering tied to bounded deferred checks;
- docs and verifier output use the same terminology.

### Phase 2 — Malformed-Input WAF Safety Contract

Plan: `plans/ci_truthful_closure_followup_phase_02_malformed_input_waf_safety.md`

Goal: determine and enforce the real security boundary for malformed/overlong UTF-8 payloads, especially the current XSS corpus case.

Primary outputs:

- proof of whether malformed bytes reach the WAF and in what form;
- one explicit behavior contract: reject, canonicalize safely, or scan losslessly;
- regression coverage for malicious and benign malformed input;
- no known bypass documented as a harmless stale expectation without boundary evidence.

### Phase 3 — Evidence Reconciliation and Final Closure

Plan: `plans/ci_truthful_closure_followup_phase_03_evidence_reconciliation.md`

Goal: synchronize implementation, plans, docs, timing evidence, and final-head proof before restoring `COMPLETE` status.

Primary outputs:

- exact final SHA recorded after all implementation commits;
- fresh `verify`, `verify-full`, and `verify-release` evidence from that final code state;
- hosted routine proof from the final implementation or an explicitly justified immediately preceding equivalent commit;
- current verification contract matches `verify.rs` exactly;
- failure ledger reflects final rather than intermediate dispositions;
- branch protection remains `EXTERNALLY UNVERIFIED` unless settings are actually inspected.

## 4. Ordering

Phases 1 and 2 are independent implementation tracks and may be executed in either order. Phase 3 must be last.

Recommended sequence:

1. Phase 1 — release qualification semantics;
2. Phase 2 — malformed-input/WAF safety;
3. targeted owning-crate tests after each change;
4. Phase 3 — one consolidated full/release proof and documentation reconciliation.

Do not run repeated full-workspace verification after every small edit. Use focused tests during Phases 1 and 2 and reserve broad authoritative runs for Phase 3 unless a focused failure requires escalation.

## 5. Global acceptance criteria

This follow-up roadmap is complete only when all of the following are true:

1. `cargo xtask verify` passes on the final clean head.
2. `cargo xtask verify-full` passes on the final clean head with no hidden exclusion created for this work.
3. `cargo xtask verify-release` passes according to a truthful package-qualification contract.
4. Every publishable crate is reported with one explicit release state; no skipped crate is described as successfully assembled or verified.
5. A crate blocked only by unpublished internal predecessors names those predecessors and the exact manual follow-up check required after publication.
6. The verifier never runs actual `cargo publish` and never consumes registry credentials.
7. Dirty-tree release verification still fails by default; `--allow-dirty` remains diagnostic-only.
8. The overlong/malformed UTF-8 XSS case has an evidence-backed security disposition, not merely a test expectation documenting non-detection.
9. Malicious malformed-input regression tests and benign controls pass at the actual boundary being claimed.
10. `docs/testing/verification-contract.md` accurately describes the current commands and semantics.
11. The Phase 1 failure ledger has a final-state summary consistent with the final full-suite result.
12. The authoritative closure-results document records the exact committed SHA used for final evidence.
13. Hosted routine timing is described accurately: observed duration, cache state, target, and blocking threshold are distinct facts.
14. No `COMPLETE` document contains a current blocker, stale final SHA, contradictory timing statement, or false package-qualification claim.
15. Branch protection is either directly verified or explicitly left `EXTERNALLY UNVERIFIED`.

## 6. Stop conditions

Keep this roadmap `INCOMPLETE` if any of the following remains:

- a publishable crate is silently omitted from qualification;
- the verifier reports skipped work as successful work;
- malformed/overlong input can reach enforcement logic in a form that bypasses an advertised detection guarantee and no safe upstream rejection exists;
- a security-sensitive corpus expectation is weakened without contract evidence;
- `verify-full` or `verify-release` fails on the final clean head;
- current documentation describes commands or behavior that do not exist;
- closure evidence refers to an uncommitted or stale SHA;
- hosted timing is represented as meeting a target that the recorded run did not meet;
- external branch settings are claimed as verified without direct evidence.

## 7. Handoff guidance

This is a closure pass, not a new infrastructure project. Prefer narrow code changes, direct tests, and explicit evidence over abstractions. If Cargo semantics prevent a pre-publication proof for a path-dependent crate, represent that limitation honestly and bind it to the manual publication sequence rather than adding a local registry or automating publication.
