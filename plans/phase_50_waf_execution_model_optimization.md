# Phase 50 Plan: WAF Execution-Model Optimization

Status: implemented and closed; retained as historical handoff detail. Closeout: `architecture/performance_optimization_closeout.md`.

Roadmap: `plans/performance_optimization_roadmap.md`.

Baseline: Phase 49 recorded evidence at the implementation head.

Depends on: Phase 49 complete.

## Objective

Reduce scheduler, allocation, clone, and ownership overhead in `synvoid-waf` attack detection while preserving every detector, normalization rule, anomaly score, enforcement outcome, and public API.

The current implementation creates a Tokio `JoinSet` per request and spawns synchronous detector routines into individual Tokio tasks. Because the unified worker already processes many requests concurrently, this intra-request async fanout may create more scheduler work than useful parallelism. Phase 49 must decide this with evidence.

## Scope

Canonical implementation owner:

`crates/synvoid-waf/src/attack_detection/`

Root `src/waf/attack_detection/` remains a compatibility facade and must not regain implementation ownership.

Primary API to preserve:

`AttackDetector::check_request(...).await -> (Option<AttackDetectionResult>, u32)`

Do not make callers adopt a new signature to obtain the optimization.

## Workstream A — Implement a borrowed synchronous evaluation core

Create an internal synchronous detector-evaluation function or equivalent private structure that can operate on borrowed:

- path;
- query;
- `HeaderMap`;
- body bytes;
- normalized inputs.

The public async `check_request()` may remain async and delegate to this core.

Goals:

- avoid `JoinSet` task allocation for synchronous detector functions;
- avoid `Arc<HeaderMap>` created solely for spawned-task ownership;
- avoid `Arc<[u8]>` / `body.to_vec()` created solely for spawned-task ownership;
- avoid `NormalizedInputs::into_owned()` solely to make spawned futures `'static`;
- preserve fast-path pre-screen behavior;
- preserve header-validation and max-body-size checks.

Do not duplicate detector logic into a second implementation. Existing internal `check_*_internal` helpers should remain the canonical detector calls where practical.

## Workstream B — Preserve anomaly-scoring semantics exactly

Default anomaly scoring is enabled.

When anomaly scoring is enabled:

- run all enabled detectors required by current semantics;
- sum the same detector scores;
- preserve attack-priority selection defined by `attack_priority()`;
- preserve strict-normalization contribution;
- preserve standalone behavioral anomaly contribution;
- preserve size/header-validation contribution.

Do not short-circuit after the first detection when scoring currently requires the complete score.

When anomaly scoring is disabled:

- early terminal detection may remain short-circuiting;
- outcome-first compatibility is authoritative;
- do not weaken coverage to obtain lower latency.

Add differential tests that execute old/reference behavior and the new evaluation core over a corpus of benign and multiply-matching malicious inputs. Exact `AttackType` is diagnostic where the existing contract permits multiple valid categories, but anomaly-enabled priority behavior must remain deterministic.

## Workstream C — Decide inline versus whole-stage offload from evidence

Preferred implementation if Phase 49 supports it: borrowed inline evaluation on the unified worker, because it removes per-detector scheduling and ownership overhead.

However, the project performance contract also says CPU-heavy work should not stall the unified event loop.

Therefore:

1. measure the borrowed inline implementation under benign and suspicious concurrency;
2. compare worker event-loop lag and p99 to the Phase 49 `JoinSet` baseline;
3. if inline evaluation materially improves throughput/latency without harmful event-loop lag, keep it simple;
4. if expensive large-body/full-detector work still stalls the event loop, evaluate one bounded offload for the entire attack-detection stage, not one task per detector.

Any whole-stage offload MUST:

- use an existing bounded CPU/offload mechanism or an explicitly bounded semaphore;
- define timeout/rejection behavior;
- preserve fail-closed policy where current request handling requires it;
- avoid serializing/copying large bodies across process boundaries unless evidence justifies the trade;
- not introduce an unbounded `spawn_blocking` fanout.

Do not force cross-process WAF offload into this phase if the measurements do not justify it. Record it as a residual instead.

## Workstream D — Reduce unnecessary normalization/clone work

Audit whether request-smuggling/JWT paths and the generic normalized detector set can share borrowed normalization results.

Specific targets:

- query-string `to_string()` currently needed only for spawned ownership;
- shared header/body clones;
- `String::from_utf8_lossy` followed by normalization where normalized request data already exists;
- duplicate normalization between detector families.

Security invariant: raw-byte SQLi/XSS detection remains available; normalization optimization must not remove the raw input path added for hostile encoding coverage.

## Workstream E — Preserve fast path and detector configuration

Tests must cover:

- each detector individually enabled/disabled;
- all detectors enabled;
- strict normalization on/off;
- anomaly scoring on/off;
- empty/no body;
- binary/non-UTF8 body;
- over-limit body;
- smuggling-relevant headers;
- JWT in header/query/body;
- multiply-matching payloads.

No detector may silently become unreachable because the old task-spawn branch was removed.

## Workstream F — Benchmark comparison

Use the corrected Phase 49 harness.

At minimum compare:

- benign path-only;
- benign headers/query;
- 1 KiB body;
- 10 KiB body;
- SQLi/XSS representative inputs;
- request smuggling;
- JWT;
- 1/8/32/128 concurrent requests;
- event-loop lag under sustained suspicious traffic.

Capture before/after task count if the existing runtime instrumentation makes that practical.

## Acceptance criteria

Phase 50 is complete only when:

- `AttackDetector::check_request()` public API is unchanged;
- detector/config surface is unchanged;
- no detector is disabled or sampled;
- anomaly-enabled scores and priority outcomes match the existing contract;
- security regression/WAF suites are green;
- the new execution model has Phase 49-comparable evidence;
- no material regression exists in representative benign or suspicious request throughput/tail latency;
- event-loop fairness is not materially worse;
- per-request detector `JoinSet` fanout is removed if the evidence supports the expected win, or the plan records why it was retained;
- ownership clones used solely for spawned tasks are removed where the final execution model no longer requires them.

## Verification

```bash
cargo test -p synvoid-waf --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
cargo bench --bench bench_normalization
cargo bench --bench bench_attack_detection_wave10
cargo xtask verify
cargo xtask verify-full
```

Run the Phase 49 concurrency/event-loop harness with identical configuration.

## Rejection criteria

Reject the implementation if it:

- turns async task removal into detector removal;
- changes anomaly score totals or enforcement precedence unintentionally;
- relies on exact-category test weakening to hide missed detections;
- introduces unbounded blocking/offload work;
- copies the full body merely to move it to another executor without measured justification;
- produces a microbenchmark win while materially worsening concurrent p99 or worker event-loop lag.
