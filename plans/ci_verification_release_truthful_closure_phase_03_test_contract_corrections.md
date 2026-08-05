# Phase 3 — Test Contract and Expectation Corrections

**Status:** COMPLETE  
**Roadmap:** `plans/ci_verification_release_truthful_closure_roadmap.md`  
**Depends on:** Phase 1 adjudication; Phase 2 for any reclassified product defects  
**Purpose:** Correct only those tests proven to assert obsolete behavior while preserving meaningful product and security guarantees.

## 1. Entry Criteria

A test may enter this phase only when the Phase 1 ledger records:

- the exact failing assertion;
- the intended current contract;
- an authoritative source or an explicit contract decision;
- why current behavior is intentional rather than accidental;
- why the expectation change does not reduce a security, persistence, routing, or protocol guarantee;
- the replacement assertion that will still detect a meaningful regression.

Any security-sensitive test that lacks this evidence remains a Phase 2 product-regression candidate.

## 2. Governing Rule

Do not update a test merely to mirror current implementation output.

A valid stale-expectation correction must move the test toward an externally meaningful contract. Prefer assertions about:

- allow/block/challenge outcome;
- durable state;
- configured routing semantics;
- canonical public API behavior;
- mathematically correct result;
- documented threshold boundary;
- observable cache contents or promotion behavior;
- accepted category set when multiple categories are intentionally valid.

Avoid assertions about private collection size, incidental enum ordering, internal helper calls, or exact implementation-specific category choice unless those are part of the public contract.

## 3. Workstream A — Proxy Routing Semantics

### A1. Unknown-host behavior

For `test_unknown_host_accepted_when_disabled`, determine the precise scope of `reject_unknown_hosts`:

- per-site host validation;
- catch-all/default-site routing;
- listener-level rejection;
- SNI versus HTTP Host behavior;
- behavior when no default route exists.

Update the architecture/configuration documentation first if it is ambiguous. The corrected test must cover both enabled and disabled states and must distinguish an intentional catch-all route from accidental acceptance.

Required cases:

- known host routes correctly;
- unknown host with rejection enabled is rejected;
- unknown host with rejection disabled follows the documented fallback only when a fallback exists;
- unknown host does not silently route to an unrelated site.

### A2. Wildcard-domain behavior

For `test_wildcard_domain_matching`, define:

- whether `*.example.com` matches exactly one label or multiple labels;
- whether the apex `example.com` matches;
- precedence between exact, wildcard, and catch-all routes;
- normalization of case and trailing dot;
- duplicate wildcard insertion behavior.

Revise the test to assert the documented routing table semantics rather than the current insertion implementation. If current production behavior violates the decided semantics, move the item back to Phase 2.

## 4. Workstream B — ICMP Validation Contract

For `test_icmp_type_rule_validation`, decide whether address-family-specific ICMP type validation is intentionally unsupported, partially implemented, or required by the public configuration contract.

Allowed resolutions:

1. If validation is required, reclassify as a product defect and implement it in Phase 2.
2. If the API intentionally accepts a family-agnostic rule representation, update the test and documentation to assert the actual validation boundary.
3. If the parameter is obsolete, remove it through a narrow API cleanup only when doing so does not expand this phase into a compatibility project.

Do not retain a misleading unused parameter and simply weaken the test without documenting the behavior.

## 5. Workstream C — Mathematical and Threshold Expectations

### C1. Entropy

For `test_entropy_two_characters`, use the mathematically correct Shannon entropy for a balanced two-symbol distribution. The test should use an appropriate tolerance and include:

- one-symbol distribution;
- balanced two-symbol distribution;
- a simple non-balanced distribution;
- empty-input behavior if part of the API contract.

This is a test correction unless the implementation computes the value incorrectly.

### C2. Circuit threshold

For `test_provider_stats_record_failure_circuit_open`, decide whether the circuit opens at `>= threshold` or only after exceeding it. Align:

- configuration documentation;
- implementation;
- metrics/state transition;
- test boundary cases at threshold minus one, exactly threshold, and threshold plus one.

If existing documentation promises the opposite boundary, treat the implementation as a product defect rather than changing the test.

## 6. Workstream D — Defaults and Cache Observability

### D1. Anomaly-scoring default

`test_anomaly_scoring_default_disabled` may be corrected here only if Phase 1 establishes the intended default from an explicit security/configuration decision. Update all relevant default constructors, sample configuration, reference documentation, and test together if they disagree.

The test must assert the public default and explicit opt-in/opt-out override behavior. It must not infer the default from one internal struct alone.

### D2. Tiered-cache promotion

For `test_tiered_cache_l2_promotion` and `test_tiered_cache_multiple_keys`, identify the intended observable behavior:

- item availability after L1/L2 lookup;
- promotion into L1;
- eviction order;
- per-tier length semantics;
- asynchronous write/promotion completion.

Prefer behavior assertions over direct `l2_len` implementation details unless tier length is a supported API. If eventual promotion is intentional, use a deterministic synchronization hook or awaited operation rather than arbitrary sleep.

## 7. Workstream E — WAF Category and Outcome Expectations

This workstream handles only cases where Phase 1 proves the request receives the correct security outcome and only the expected category or incidental result is stale.

Candidates may include:

- open redirect payload categorized as XSS or RFI;
- encoded path traversal categorized as command injection;
- XXE payload categorized as XSS;
- streaming malicious content returning `Block` rather than `Continue`;
- custom configuration changing the exact result variant while preserving the documented enforcement outcome.

### E1. Category contract

For each candidate, choose one model and document it:

- **Canonical category:** exactly one category is guaranteed.
- **Allowed category set:** several categories are valid because signatures overlap.
- **Outcome-first:** the public contract guarantees malicious detection/enforcement, while category is diagnostic and may vary.

Tests must match the selected model. An outcome-first test should still assert that the diagnostic category is non-benign and useful; it should not discard all classification checks.

### E2. Missing detection is not stale

The following conditions force reclassification to Phase 2:

- no malicious category is produced;
- request is allowed when the contract requires block/challenge;
- malformed or encoded form bypasses detection;
- benign control is blocked;
- direct and streaming paths materially disagree without a documented reason.

### E3. Corpus expectations

Corpus tests should assert the corpus contract, not exact internal matcher identity. Preserve:

- malicious/benign label;
- expected enforcement outcome;
- normalization behavior;
- required minimum category confidence where exposed.

Do not rewrite corpus labels to fit current output without reviewing the payload.

## 8. Documentation Requirements

Every intentional behavior decision must be reflected in the smallest authoritative location, such as:

- configuration reference;
- proxy routing architecture document;
- WAF classification/scoring documentation;
- cache API documentation;
- inline public API documentation.

Avoid creating new policy documents when an existing source can be corrected. The verification contract should summarize test disposition, not become the primary product specification.

## 9. Implementation Sequence

For each ledger entry:

1. read the contract source recorded in Phase 1;
2. run the focused failing test unchanged;
3. confirm current product behavior matches the intended contract;
4. update or add the contract documentation if needed;
5. replace the stale assertion with the strongest meaningful assertion;
6. add adjacent boundary/control cases where the prior test was underspecified;
7. run the focused test and owning crate suite;
8. run `cargo xtask verify`;
9. update the ledger with the correcting commit and command.

Expectation-only changes should normally avoid production-code edits. If production code must change to expose a stable public result or correct documentation mismatch, keep the change narrow and explain why the item remains a contract correction rather than a product regression.

## 10. Prohibited Shortcuts

Do not:

- replace exact assertions with `is_ok()` or non-panicking checks;
- accept any attack category, including benign/unknown categories;
- remove malicious corpus entries;
- lower expected score thresholds without contract evidence;
- add broad tolerances that hide incorrect values;
- add sleeps for cache or routing behavior;
- mark tests ignored;
- exclude tests from nextest;
- rename a product defect as stale after implementation work has begun;
- change public defaults without updating configuration documentation.

## 11. Acceptance Criteria

Phase 3 is complete only when:

- every Phase 1 `STALE_EXPECTATION` row assigned here is resolved;
- each revised test names or clearly encodes the intended contract;
- security-sensitive cases preserve detection/enforcement and benign-control assertions;
- proxy host and wildcard behavior are documented and covered at their boundaries;
- ICMP validation behavior is explicit and not represented by misleading dead parameters;
- entropy expectations are mathematically correct;
- circuit threshold behavior is tested below, at, and above the boundary;
- anomaly-scoring default behavior agrees across code, configuration, and docs;
- cache tests use deterministic completion and observable behavior;
- category-overlap tests use an explicit canonical/set/outcome-first model;
- focused tests and owning crate suites pass;
- `cargo xtask verify` passes;
- no test is ignored, excluded, or weakened to a non-meaningful assertion;
- no CI or release automation is added;
- the Phase 1 ledger records the final contract source and correcting commit for every row.

## 12. Closure Evidence

Record:

- old assertion and why it was obsolete;
- authoritative intended contract;
- new assertion and why it remains regression-sensitive;
- documentation changed;
- focused command result;
- owning crate suite result;
- any item reclassified back to Phase 2 or Phase 4, with rationale.