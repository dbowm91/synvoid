# CI Truthful Closure Follow-up — Phase 2: Malformed-Input WAF Safety Contract

**Status:** PLANNED  
**Created:** 2026-08-08  
**Roadmap:** `plans/ci_truthful_closure_followup_roadmap.md`  
**Baseline reviewed:** `584e6fa05b5e570a13140105ca85fb237dc65468`

## 1. Objective

Resolve the remaining security-sensitive ambiguity around malformed and overlong UTF-8 input, especially the current corpus case where an XSS-like payload using overlong encodings is expected not to be detected.

This phase must establish the actual product security boundary before deciding whether the correct fix belongs in:

- HTTP request parsing;
- percent decoding/canonicalization;
- the WAF normalizer;
- raw-byte detector fallback;
- or the test contract.

The goal is not to build a new parser or broaden WAF scope. The goal is to prove that malformed input cannot bypass an advertised enforcement boundary simply because text normalization loses or transforms bytes.

## 2. Current ambiguity

The existing corpus test for `xss_invalid_utf8` now asserts that no detection occurs and describes overlong UTF-8 handling as a known limitation.

That disposition is insufficient for closure unless one of the following is demonstrated:

1. the actual HTTP/request boundary rejects this malformed representation before WAF enforcement is expected;
2. canonicalization safely maps the representation into the intended dangerous ASCII form before detection;
3. the WAF scans the relevant raw bytes/decoded octets losslessly enough to detect the malicious construct;
4. the advertised contract explicitly excludes the representation for a defensible protocol reason and a request cannot reach application/upstream processing in a dangerous interpreted form.

A unit-level non-detection is not by itself evidence that the deployed request path is safe.

## 3. Security contract to establish

Select exactly one primary malformed-input policy for each relevant input surface.

Permitted policy classes:

### A. Reject malformed input

Use when the HTTP/URI/body parser treats invalid encodings as invalid protocol/application input.

Required proof:

- the rejection happens before unsafe downstream interpretation;
- the response/outcome is deterministic;
- the WAF does not need to classify an attack that cannot pass the request boundary;
- a regression test exercises the real boundary rather than only a helper.

### B. Canonicalize then scan

Use when SynVoid intentionally accepts encoded input and normalizes it.

Required proof:

- canonicalization is deterministic and bounded;
- dangerous overlong/noncanonical forms resolve to the same semantic bytes as their canonical form where appropriate;
- normalization is idempotent or deliberately multi-pass with a fixed cap;
- malicious and benign controls behave consistently.

### C. Lossless/raw-byte scan

Use when the application permits malformed/non-UTF8 bytes and WAF detection must operate before lossy conversion.

Required proof:

- relevant request components preserve bytes long enough for scanning;
- detectors receive the correct octet sequence;
- raw-byte and normalized-text paths do not contradict each other;
- attack classification/outcome remains deterministic enough for the documented contract.

Do not silently mix policies between path/query/body without documenting the difference.

## 4. Workstream A — Trace the real request path

For the current malformed XSS fixture and a canonical XSS control, trace data through the actual SynVoid request pipeline.

At minimum determine, with code references and focused instrumentation/tests if needed:

1. where percent decoding occurs;
2. whether path and query are decoded by the HTTP library before SynVoid sees them;
3. whether request bodies are treated as bytes or UTF-8 strings;
4. where lossy UTF-8 conversion occurs;
5. what exact bytes/string reach `AttackDetector::check_request`;
6. what exact representation reaches `XssDetector` and `SqliDetector`;
7. whether an upstream application would see the same representation as the WAF;
8. whether malformed URI encodings are rejected earlier by Hyper/HTTP parsing or SynVoid's own routing layer.

Prefer tests over temporary logging in committed production code.

## 5. Workstream B — Reproduce with a small bounded corpus

Create a compact table of malicious and benign controls. Do not build a large fuzzing project.

Minimum malicious cases:

- canonical `<script>alert(1)</script>`;
- percent-encoded canonical ASCII equivalent;
- malformed/overlong representation matching the existing corpus intent;
- malformed bytes adjacent to otherwise canonical XSS syntax;
- one SQLi malformed-input case already covered by raw-byte detection, used as a comparison baseline.

Minimum benign controls:

- ordinary UTF-8 non-ASCII text;
- percent-encoded benign Unicode;
- malformed input that should be rejected but does not contain an attack signature;
- benign byte sequences adjacent to percent signs/escape-like text.

Record for each case:

- parser acceptance/rejection;
- bytes/string presented to WAF;
- detection result;
- enforcement outcome;
- downstream representation if the request would continue.

## 6. Workstream C — Choose the minimum safe correction

After Workstreams A and B, implement the smallest correction consistent with the real boundary.

### If the real boundary rejects the malformed representation

- add an integration-level regression test proving rejection;
- change the corpus test so it does not claim a WAF bypass is acceptable merely because a unit helper does not detect it;
- document that malformed input safety is enforced at the parser/request boundary;
- keep unit WAF behavior documented only as an internal limitation if it is impossible for that representation to reach the WAF in production.

### If the malformed representation can reach downstream processing

Then non-detection is not acceptable if downstream semantics can interpret it as dangerous input.

Choose the smallest suitable fix:

- preserve raw bytes for XSS scanning as already done for SQLi where viable;
- add bounded canonicalization for known noncanonical encodings if standards and parser behavior justify it;
- reject malformed encoding before forwarding;
- or otherwise align WAF and downstream interpretation.

Do not add a giant alternate Unicode/HTML parser unless evidence shows it is required.

## 7. Workstream D — Normalizer safety properties

Review only the normalization behaviors implicated by this line of work.

Require tests for:

- bounded decoding depth;
- idempotency or explicitly bounded repeated decoding;
- no newly introduced encoded sequences escaping a final scan;
- no lossy conversion before a required raw-byte scan;
- preservation of benign Unicode;
- canonical dangerous payload and encoded equivalents converging to an equivalent enforcement result when they are accepted.

If post-NFKC decoding remains necessary, prove it cannot create an unbounded decode loop.

## 8. Workstream E — Detection-result contract

Do not overfit exact attack taxonomy where multiple detectors legitimately match the same payload.

For security closure, distinguish:

- **enforcement invariant:** malicious request is rejected/blocked/challenged according to policy;
- **classification invariant:** attack family is exact only where externally meaningful;
- **observability invariant:** overlapping classification remains diagnosable.

Tests may accept a bounded set of attack classifications only when the enforcement invariant is preserved and the overlap is documented.

Do not weaken a malicious test to "any result is fine" if the request can pass through undetected.

## 9. Workstream F — Focused tests

At minimum add/retain tests proving:

1. canonical XSS is detected/enforced;
2. canonical percent-encoded XSS has the intended equivalent outcome;
3. malformed/overlong XSS is either rejected before forwarding or detected/enforced;
4. benign malformed input follows the selected policy without being mislabeled as malicious solely due to malformed encoding;
5. SQLi invalid-byte behavior remains protected;
6. benign UTF-8/Unicode remains unaffected;
7. normalization does not require unbounded repeated decoding;
8. streaming and buffered WAF paths do not diverge for the same accepted canonicalized payload where both paths are in scope.

Use existing corpus/integration infrastructure where practical.

## 10. Evidence requirements

Before marking this phase complete, create a short evidence section in the phase plan or a companion result file recording:

- chosen malformed-input policy by surface (path/query/body if different);
- exact test names and commands;
- whether the existing overlong XSS representation is parser-rejected, normalized, or raw-scanned;
- production code changed, if any;
- why the final disposition is safe;
- any intentionally unsupported representation and the boundary that makes it non-exploitable.

A statement such as "known limitation" without a boundary proof is insufficient.

## 11. Validation sequence

During implementation, keep validation focused:

1. targeted WAF normalizer/detector unit tests;
2. `cargo nextest run -p synvoid-waf` with an appropriate test filter or target;
3. targeted HTTP/request-pipeline integration test if parser rejection is the selected boundary;
4. directly adjacent streaming/corpus tests;
5. `cargo xtask verify` once after the phase is coherent.

Reserve `cargo xtask verify-full` for Phase 3 unless focused results indicate a broader regression.

## 12. Acceptance criteria

Phase 2 is complete only when:

- [ ] the actual request-path representation of malformed/overlong input is known and tested;
- [ ] one explicit malformed-input policy exists for each relevant request surface;
- [ ] the current overlong XSS case is either rejected safely or detected/enforced before unsafe forwarding;
- [ ] no malicious corpus case is changed to `Pass` solely because the existing detector misses it;
- [ ] benign malformed/Unicode controls exist and pass according to the chosen policy;
- [ ] raw-byte and normalized-text handling are ordered deliberately;
- [ ] normalization remains bounded;
- [ ] exact attack taxonomy is not weakened unless enforcement remains intact and overlap is documented;
- [ ] focused WAF and boundary tests pass;
- [ ] documentation describes the real boundary rather than a helper-level assumption;
- [ ] no broad parser framework or unrelated WAF feature expansion is introduced.

## 13. Stop conditions

Do not mark this phase complete if:

- the malformed representation can reach downstream processing with dangerous semantics while WAF enforcement misses it;
- safety is inferred solely from a unit test helper;
- lossy UTF-8 conversion occurs before the only available attack scan for bytes that can reach downstream consumers;
- a malicious expectation is weakened without parser/enforcement evidence;
- the fix relies on unbounded decode/canonicalization loops;
- benign Unicode handling regresses materially;
- implementation expands into a new WAF architecture unrelated to the demonstrated defect.

## 14. Handoff note

This phase should be evidence-led. First determine what bytes actually cross each boundary; only then choose rejection, canonicalization, or raw-byte scanning. The preferred implementation is the narrowest one that makes the WAF/request boundary and downstream interpretation agree on whether malformed input is safe to forward.
