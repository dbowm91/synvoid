# Phase 1 — Current-Head Failure Adjudication

**Status:** PLANNED  
**Roadmap:** `plans/ci_verification_release_truthful_closure_roadmap.md`  
**Baseline:** `f8c19b0f8c4abe73818ae8794d45abcf293d9b78` plus planning commits  
**Purpose:** Establish a reproducible, contract-backed disposition for every failure or timeout before product code or expectations are changed.

## 1. Problem Statement

The current verification contract contains a provisional table classifying the observed `verify-full` failures as:

- five real product regressions;
- twenty-one stale expectations;
- two environment-dependent tests;
- three harness or timeout defects.

That table is useful as an inventory but is not sufficient closure evidence. Several entries labeled stale are security-sensitive WAF tests where the current implementation either does not detect an attack, assigns a different attack category, blocks normal encoded text, or changes streaming behavior. Current behavior cannot be used as the sole proof that the test is obsolete.

This phase creates the authoritative ledger that all later phases must follow.

## 2. Scope

### In scope

- clean reproduction of `cargo xtask verify`, `cargo xtask verify-full`, and `cargo xtask verify-release`;
- exact enumeration of failures, timeouts, panics, prerequisite failures, and package-verification skips;
- contract adjudication for each failing test;
- validation of the current `verify-full` and `verify-release` command composition;
- validation that no test is silently excluded by nextest filters, feature selection, package selection, or wrapper behavior;
- identification of the minimal subsystem and owner for each resolution;
- creation of a durable failure ledger and execution evidence file.

### Out of scope

- modifying product behavior;
- changing test expectations;
- adding ignores or exclusions;
- increasing global timeouts;
- changing CI topology;
- changing release publication policy;
- marking any prior roadmap complete.

## 3. Required Baseline Capture

Run from a clean checkout of the current implementation head.

Record:

```bash
git rev-parse HEAD
git status --porcelain
rustc -Vv
cargo -V
cargo nextest --version
protoc --version
uname -a
```

Confirm the working tree is clean before collecting authoritative results.

Run and retain complete stdout, stderr, exit code, start time, end time, and wall-clock duration for:

```bash
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

If `verify-release` cannot begin because the tree becomes dirty due to generated files, that is itself a release-verifier defect and must be recorded rather than bypassed.

Also capture command expansion without execution:

```bash
cargo xtask verify --dry-run
cargo xtask verify-full --dry-run
cargo xtask verify-release --dry-run
```

The dry-run output must match the documented contracts and actual wrapper behavior.

## 4. Failure Ledger Schema

Create or update a closure evidence document with one row per independently resolvable failure. Each row must include:

| Field | Requirement |
|---|---|
| Test or step | Exact test binary/test name or verifier step name |
| Command | Smallest deterministic reproducer |
| Package/subsystem | Owning crate or root integration area |
| Observed result | Assertion, panic, timeout, prerequisite error, or skip reason |
| Intended contract | Product/security/protocol/persistence behavior being asserted |
| Contract source | Code API, configuration semantics, architecture document, release contract, or explicit new decision |
| Classification | PRODUCT_REGRESSION, STALE_EXPECTATION, HARNESS_DEFECT, or SPECIALIST_ENVIRONMENT |
| Security sensitivity | YES/NO with explanation |
| Resolution phase | Phase 2, 3, or 4 |
| Allowed change surface | Minimal product/test/harness files expected to change |
| Acceptance test | Exact command that proves resolution |

Do not group multiple tests into one row when they can fail for different reasons. The five proxy pipeline tests may share one root-cause entry only if the same ALPN setup defect is proven to cause all five failures.

## 5. Classification Rules

### 5.1 Product regression

Classify as a product regression when the implementation violates an intended invariant or externally meaningful behavior, including:

- persisted state resurrects an explicitly removed block after restart;
- benign input receives a non-benign anomaly score or enforcement outcome;
- known malicious input is not detected or blocked when the product claims coverage;
- streaming/chunk boundaries permit an attack that the non-streaming path detects;
- normalized or encoded input creates a material false positive;
- routing semantics contradict documented configuration behavior;
- a package or release check can pass while producing an invalid publication graph.

### 5.2 Stale expectation

Classify as stale only when all of the following are true:

1. the current behavior is intentional;
2. the intended behavior is documented or documented in the same corrective commit;
3. the behavior does not reduce a security, persistence, protocol, or routing guarantee;
4. the test asserts an obsolete output, threshold boundary, default, statistic, or incidental internal state;
5. the revised test will still fail for a meaningful regression.

A different attack category is not automatically stale. First decide whether the contract requires one canonical category, permits a set of categories, or primarily requires a blocking/detection outcome.

### 5.3 Harness defect

Classify as a harness defect only when product behavior cannot be reached or measured due to setup or synchronization failures, such as:

- missing temporary listener/socket;
- malformed TLS test configuration;
- process fixture not launched or cleaned up;
- test runtime deadlock unrelated to product lock ordering;
- timeout caused by a known fixture sleep or absent readiness signal.

### 5.4 Specialist environment

Use this category sparingly. A test may be specialist-only only when it genuinely requires an external service, privilege, platform capability, or long-running environment that cannot reasonably be replaced by a self-contained fixture. The command must have a deterministic prerequisite check and clear operator instructions.

## 6. Mandatory Security-Sensitive Re-adjudication

The following current classifications must be reviewed as presumptive product/security defects until evidence proves otherwise:

- `test_ldap_injection`;
- `test_sqli_boolean_based`;
- `test_sqli_time_based`;
- `test_xpath_injection`;
- `test_false_positive_url_encoding_normal_text`;
- `test_waf_corpus_sqli_with_invalid_utf8`;
- `test_waf_corpus_xss_invalid_utf8`;
- `test_open_redirect_with_data_protocol`;
- `test_open_redirect_with_protocol`;
- `test_path_traversal_double_encoded`;
- `test_path_traversal_encoded`;
- `test_xxe_external_entity`;
- `test_streaming_waf_large_body_handling`;
- `test_streaming_waf_config_chunk_size`;
- `test_streaming_waf_with_custom_config`.

For each case, record separately:

- whether the request is detected;
- whether it is blocked, allowed, challenged, or only scored;
- the primary and secondary categories, if supported;
- the normalization path used;
- whether the same payload behaves consistently across direct, corpus, and streaming paths;
- whether a benign control payload remains allowed.

## 7. Command-Composition Audit

Confirm that `verify-full`:

- has one broad workspace test pass rather than routine test duplication;
- includes the intended feature set;
- includes root integration tests and publishable workspace crates;
- excludes only intentionally non-workspace or fuzz targets;
- does not hide failures through a default filter;
- uses bounded per-test timeout behavior appropriate to the test groups.

Confirm that `verify-release`:

- begins with the intended full verification contract;
- checks clean-tree state before producing release evidence;
- validates all publishable metadata;
- validates internal path dependency version requirements using Cargo metadata;
- inspects package file lists using path-aware rules;
- assembles every publishable crate with `cargo package --no-verify`;
- attempts `cargo package --verify` only where dependencies are registry-resolvable;
- clearly reports every skipped packaged-source check;
- contains no path to actual publication.

## 8. Deliverables

The implementation handoff must produce:

1. a current-head command/evidence record;
2. a complete failure ledger using the schema above;
3. a corrected disposition summary with counts derived from the ledger;
4. explicit mapping of every row to Phase 2, 3, or 4;
5. a list of any documentation claims contradicted by current execution;
6. a list of any hidden exclusions, ignored tests, or wrapper skips discovered;
7. a clean diff proving no product or expectation changes occurred in this phase.

The ledger may be added as a new file under `plans/` or incorporated into the existing closure-results document, but it must remain easy to compare against final Phase 5 evidence.

## 9. Acceptance Criteria

Phase 1 is complete only when:

- all three authoritative commands have been attempted from a clean current head;
- routine verification passes or its failures are included in the ledger;
- every full/release failure, timeout, panic, prerequisite error, and package skip is represented exactly once;
- every ledger entry names an intended contract and contract source;
- every security-sensitive WAF entry has been re-adjudicated using outcome and benign-control evidence;
- no classification relies solely on current implementation behavior;
- no test has been modified, ignored, filtered, or weakened;
- no product code has been modified;
- no CI workflow has been added or expanded;
- the corrected counts and phase mapping are internally consistent;
- the phase document is updated from `PLANNED` only after the evidence file is committed.

## 10. Failure Conditions

Stop and keep the phase incomplete if:

- the current head cannot be reproduced from a clean checkout;
- command wrappers and documentation disagree and the disagreement is not resolved;
- a test cannot be classified without an unresolved product decision;
- security-sensitive behavior is proposed as stale without documented intent;
- any failure is suppressed to continue the suite;
- generated files make a clean `verify-release` impossible;
- package verification silently skips a crate without an explicit reason.

Unresolved decisions must remain visible as blockers for the relevant later phase.