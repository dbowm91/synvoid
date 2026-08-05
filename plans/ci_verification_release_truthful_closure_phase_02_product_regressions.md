# Phase 2 — Product and Security Regression Repair

**Status:** COMPLETE  
**Roadmap:** `plans/ci_verification_release_truthful_closure_roadmap.md`  
**Depends on:** Phase 1 failure ledger and contract adjudication  
**Purpose:** Correct all failures proven to be product regressions without broad redesign or test weakening.

## 1. Entry Criteria

Do not begin this phase until Phase 1 has:

- reproduced the failures on a clean current head;
- recorded the exact failing assertions and inputs;
- identified the intended product/security contract;
- mapped each confirmed product defect to this phase;
- distinguished implementation defects from stale expectations and harness defects.

The current provisional minimum is:

- one block-store restart/unblock persistence defect;
- three anomaly-scoring defects;
- one streaming multi-chunk SQL injection defect.

Additional security-sensitive WAF entries from the current stale-expectation list must move into this phase whenever Phase 1 determines that detection, blocking, normalization, classification, or false-positive behavior violates the intended contract.

## 2. Scope Boundaries

### In scope

- block-store replay/state reconciliation required to preserve explicit unblock operations across restart;
- WAF anomaly-score correctness for benign and malicious inputs;
- streaming WAF detection across chunk boundaries;
- query-string, encoded-input, invalid-UTF-8, and attack-category behavior adjudicated as product defects;
- minimal documentation updates required to state the corrected contract;
- focused regression tests and benign controls.

### Out of scope

- a block-store architecture rewrite;
- replacement of the WAF engine or ruleset framework;
- broad attack taxonomy redesign;
- adding new attack families unrelated to the failing ledger;
- threshold tuning based only on one test fixture;
- performance optimization unrelated to the corrected behavior;
- CI expansion;
- disabling or excluding tests.

## 3. Workstream A — Block-Store Restart/Unblock Invariant

### A1. Reproduce the state transition

Establish the shortest deterministic sequence for the failing invariant:

1. add or persist a block for an IP;
2. confirm the block is active;
3. explicitly unblock the IP;
4. confirm the active state and durable representation reflect the unblock;
5. restart or reconstruct the store using the same persisted data;
6. confirm the stale block does not reappear.

Capture whether the resurrection originates from:

- append-only event replay order;
- snapshot plus journal merge order;
- tombstone/unblock persistence;
- cache hydration;
- compaction;
- timestamp/version conflict handling;
- asynchronous flush completion;
- stale in-memory state written after the unblock.

### A2. Define the invariant

The authoritative invariant must be explicit:

> Once an unblock operation is acknowledged as durable, restart or replay must not restore an earlier block unless a later block operation exists.

If acknowledgements currently occur before durable persistence, either correct the durability boundary or update the API so the acknowledgement contract is truthful. Do not make the test pass by inserting arbitrary sleeps.

### A3. Implement the minimum correction

Prefer the smallest correction that restores ordering and replay truth, such as:

- durable unblock tombstone/event;
- monotonic sequence/version comparison;
- corrected snapshot/journal precedence;
- awaited flush before acknowledgement;
- prevention of stale post-unblock cache writeback.

Avoid schema migration unless the existing representation cannot encode the invariant.

### A4. Regression coverage

Add or retain deterministic tests for:

- block → unblock → restart remains unblocked;
- block → unblock → block → restart remains blocked by the latest operation;
- repeated unblock is idempotent;
- compaction or snapshotting does not remove the latest unblock state;
- concurrent readers do not observe a resurrected stale block after restart completion.

Use temporary directories and explicit flush/reopen operations. No fixed global paths.

## 4. Workstream B — WAF Anomaly Scoring

### B1. Benign zero-score behavior

For `test_anomaly_scoring_zero_score_benign_request`, determine which component contributes the unexpected score. Inspect normalized URI, headers, body, entropy/features, rule aggregation, and default baseline terms.

Acceptance requires:

- the benign control receives the documented neutral score or remains below every enforcement threshold;
- the correction does not globally suppress weak malicious signals;
- the test states why the payload is benign and which feature classes must remain inactive.

Do not simply clamp all low scores to zero unless the scoring contract explicitly requires it.

### B2. Multi-attack score accumulation

For `test_anomaly_scoring_multiple_attacks`, verify:

- all expected signals are independently detected;
- aggregation does not overwrite an earlier signal;
- deduplication does not collapse distinct attack families incorrectly;
- caps and normalization are applied after, not before, required accumulation;
- the enforcement threshold matches documented configuration.

The corrected test should assert both component evidence and final outcome where the API exposes both.

### B3. XSS score accumulation

For `test_anomaly_scoring_xss_attack`, determine whether the defect is missing XSS detection, incorrect rule weight, normalization loss, or threshold mismatch. Correct the underlying cause rather than lowering a global threshold solely to satisfy the fixture.

Include a benign HTML/control payload to protect against false positives.

### B4. Configuration/default consistency

If Phase 1 moves `test_anomaly_scoring_default_disabled` into this phase, decide and document the intended default. The implementation, generated/default configuration, user documentation, and test must agree. A security-relevant default change must not be inferred from current code alone.

## 5. Workstream C — Streaming and Chunk-Boundary Security

### C1. Multi-chunk SQL injection

For `test_streaming_waf_multiple_chunks_sqli`, identify whether the streaming path:

- scans chunks independently without overlap/state;
- loses normalized bytes between chunks;
- finalizes before the complete token is available;
- applies a different ruleset from the buffered path;
- truncates at the configured chunk boundary;
- fails to carry parser state.

Correct the minimum state-handling defect so an attack split across realistic chunk boundaries receives an outcome equivalent to the non-streaming path.

### C2. Boundary matrix

Test the same malicious payload with splits:

- before the signature token;
- inside the token;
- across percent-encoded or escaped bytes;
- one byte per chunk for a bounded small payload;
- at the configured chunk-size boundary;
- with benign payloads split at the same points.

The test matrix must be bounded and deterministic. Do not create a large property-testing project in this phase.

### C3. Large-body and custom-config behavior

If Phase 1 determines the current large-body, chunk-size, or custom-config tests represent intended product behavior, repair the implementation here. The plan must distinguish:

- expected block due to malicious content;
- expected continue/allow because scanning is deferred;
- explicit size-limit rejection;
- truncation behavior;
- configuration precedence.

A test must assert the documented outcome, not merely the current enum variant.

## 6. Workstream D — Security-Sensitive Reclassified Cases

Phase 1 may identify additional product defects among the currently provisional stale cases. Handle them using these rules.

### D1. Missing query-string detections

For SQLi, LDAP injection, and XPath injection cases:

- confirm query-string inspection is part of the advertised WAF scope;
- trace decoding and normalization before rule evaluation;
- verify malicious parameters are not omitted due to component selection;
- add benign query controls;
- preserve detection across raw and percent-encoded forms where intended.

### D2. Encoded path traversal and external-entity cases

A payload classified under a different attack category may still satisfy the primary security outcome. Decide whether the contract requires:

- exact canonical category;
- one of an allowed category set;
- at least one high-confidence malicious category plus a block/challenge outcome.

If the request is not reliably detected or blocked, fix the product. If only the category is noncanonical and the security outcome is intact, Phase 3 may update the expectation instead.

### D3. Invalid UTF-8 corpus behavior

Define how invalid byte sequences are handled before changing tests:

- reject malformed input;
- losslessly scan bytes;
- replace invalid sequences and scan normalized text;
- pass through only under an explicitly safe contract.

The chosen behavior must not create a bypass for known SQLi/XSS signatures. Add benign malformed controls where practical.

### D4. False-positive encoded normal text

If ordinary URL-encoded text triggers enforcement, correct normalization, feature extraction, or rule matching. Do not add a one-off allowlist for the fixture unless it expresses a general safe grammar.

## 7. Implementation Discipline

For each confirmed product defect:

1. add or preserve the failing regression test first;
2. verify it fails for the expected reason;
3. apply the smallest production correction;
4. run the focused test;
5. run the owning crate test suite;
6. run directly adjacent integration/security tests;
7. run `cargo xtask verify`;
8. defer `verify-full` final proof to Phase 5 after all phases are complete.

Keep commits separable by subsystem where possible:

- block-store persistence;
- anomaly scoring;
- streaming inspection;
- additional query/encoding security corrections.

## 8. Required Tests

At minimum, retain or add coverage for:

- durable unblock survives restart;
- later re-block supersedes unblock;
- benign anomaly-scoring control does not trigger enforcement;
- multi-family malicious input accumulates required evidence;
- XSS attack reaches the intended score/outcome;
- streaming SQLi split across chunk boundaries is detected;
- benign streaming controls remain allowed;
- every reclassified query/encoding defect has one malicious and one benign control;
- direct and streaming paths have equivalent security outcomes for the corrected payloads.

## 9. Acceptance Criteria

Phase 2 is complete only when:

- every Phase 1 `PRODUCT_REGRESSION` entry assigned to this phase is resolved;
- focused reproducers pass for the corrected reason;
- the block-store restart/unblock invariant is deterministic and durable;
- no arbitrary sleep is required for correctness;
- anomaly scoring correctly separates benign controls from the adjudicated attacks;
- multi-chunk inspection cannot bypass the adjudicated SQLi signature;
- any query-string, invalid-UTF-8, normalization, or false-positive defects moved into this phase are resolved with benign controls;
- tests assert externally meaningful outcomes rather than private implementation details;
- no broad threshold reduction, category erasure, fixture-specific allowlist, ignore, or exclusion is used;
- owning crate suites pass;
- `cargo xtask verify` passes;
- routine CI command composition and workflow topology are unchanged;
- Phase 1 ledger rows are updated with the fixing commit and acceptance command.

## 10. Closure Evidence

The implementation record must include:

- root cause for each defect;
- production files changed;
- tests added or strengthened;
- before/after outcome for the exact reproducer;
- benign-control result;
- focused suite results and durations;
- any contract documentation updated;
- explicit statement that no unrelated WAF or block-store redesign was performed.