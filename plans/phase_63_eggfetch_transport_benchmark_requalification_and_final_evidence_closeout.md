# Phase 63 Plan: Eggfetch Transport Benchmark Requalification and Final Evidence Closeout

Status: **complete/closed 2026-09-22.** Harness committed (`benchmarks/http_transport/`); fixture-controlled policy tests green; immutable sessions run (matrix ×2, persistence, conc2/conc8 scaling, phase-split); adjudication recorded in `architecture/eggfetch_0_2_transport_performance_requalification.md` (final authority) with one accepted, labeled tail residual. No production runtime change was required; `c3568ef4` remains the proof-bearing runtime SHA.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Reopens: performance/evidence closure only. Phase 62 runtime correctness fixes remain the production baseline.

Baseline reviewed: `main` at `c1d341c93fa49cd5e135e9b3468e6ce5cc248e47` (2026-09-22).

Current proof-bearing runtime implementation: `c3568ef4580a49edf222c5e4e6ce5d4dca904e81`.

Immutable pre-migration runtime baseline: `7083f339a43dd13d6c8f65e7acc9d03ee555b6ef`.

## Primary goal

Finish the eggfetch 0.2 campaign with reproducible, apples-to-apples transport evidence.

Phase 62 correctly fixed the runtime defects discovered after the initial migration:

- site/policy registry identity is now policy-aware;
- invalid requested TLS policy fails before network I/O;
- production remains on the eggfetch lane;
- the frozen Hyper compatibility lane remains production-inactive.

Those corrections are not reopened here.

Phase 63 exists because the Phase 62 benchmark evidence is not strong enough to support the final performance-parity claim:

1. the recorded "streaming" comparison used eggfetch native streaming after the migration but a buffered POST on the legacy baseline;
2. the legacy baseline already exposed a true generic streaming path, so the comparison could have been apples-to-apples;
3. the recorded concurrent-small-request result showed a repeatable-looking 20% throughput decrease plus materially higher p95/p99 latency, but was dismissed as noise without enough same-workload repetitions;
4. the benchmark harness source is not committed, so the recorded SHA-256 values are not independently inspectable/reproducible from the repository;
5. several policy-isolation tests use `127.0.0.1:9` as an assumed-dead endpoint rather than a fixture-controlled network condition;
6. minor documentation residue remains ("Active" heading on a closed campaign, duplicated binding text in `src/http_client/AGENTS.override.md`).

The expected terminal state remains **eggfetch adopted**. This phase must not manufacture favorable numbers, silently redefine workloads, or roll back the runtime migration merely because requalification is being performed.

## Non-goals

- No redesign of `UpstreamClientRegistry`.
- No change to Phase 62 fail-closed TLS behavior unless requalification exposes a correctness bug.
- No deletion/change of the frozen pre-campaign `synvoid-http-client` public surface.
- No outbound HTTP/3 work.
- No proxy retry, WAF, cache, auth, redirect, compression, mesh, or tunnel policy changes.
- No routine performance gate in CI.
- No broad performance campaign.
- No optimization before a repeatable regression is demonstrated and profiled.
- No benchmark result from a different host/architecture compared numerically as if it were same-host evidence.

## Workstream A — Commit a reproducible transport benchmark harness

The Phase 62 benchmark source must stop existing only as uninspectable hash evidence.

Create a repository-owned benchmark/evidence harness with a clear manual-only boundary. Preferred layout:

```text
benchmarks/http_transport/
    README.md
    common/
        ... workload/server/measurement code ...
    adapters/
        legacy_7083f339.rs
        eggfetch_current.rs
    scripts/
        run_comparison.sh
    results/
        <dated-run>.md
        <dated-run>-legacy.json
        <dated-run>-eggfetch.json
```

A different layout is acceptable if it preserves the same invariants:

- common workload generation and measurement code is shared;
- the legacy/current differences are isolated to small adapter modules;
- the exact adapter source used for each revision is committed;
- results are machine-readable plus summarized in Markdown;
- benchmark execution is manual/reference-only, not a routine CI gate.

Do not add a large runtime dependency for benchmarking. Root already has Criterion as a dev dependency, but Criterion is not mandatory if a small purpose-built async harness is clearer.

### Reproducible immutable-revision execution

The harness must be able to run against both immutable revisions without pretending the benchmark files existed in the old commit.

Preferred script behavior:

1. verify the working tree is clean;
2. create detached worktrees for:
   - legacy `7083f339a43dd13d6c8f65e7acc9d03ee555b6ef`;
   - current proof-bearing revision selected by the operator;
3. copy/overlay the committed common harness plus the revision-appropriate adapter into each worktree;
4. record:
   - source revision SHA;
   - harness commit SHA;
   - adapter file SHA-256;
   - common harness SHA-256;
   - rustc/cargo version;
   - host OS/kernel/architecture/CPU;
   - build profile;
   - environment knobs;
   - command line;
5. build each revision independently;
6. run the same workload matrix with controlled ordering;
7. write raw machine-readable results;
8. remove temporary worktrees unless `--keep-worktrees` is requested.

The old runtime revision remains immutable; only committed benchmark-only files are overlaid. Do not patch production source to make the baseline easier to benchmark.

If a compatibility shim is necessary to compile the common workload driver against the old API, keep it entirely in `adapters/legacy_7083f339.rs` and document it.

## Workstream B — Make streaming comparisons genuinely equivalent

The baseline at `7083f339...` already has:

- `send_request_streaming`;
- `send_request_streaming_generic<B>`;
- `send_request_erased_streaming`.

Do not use a buffered POST as the legacy side of a streaming performance comparison.

Build one common request body generator used on both sides. It must implement `http_body::Body<Data = Bytes>` and satisfy the stricter legacy bounds (`Send + Sync + Unpin + 'static`) so exactly the same body shape can be supplied to both implementations.

Recommended body fixture:

- deterministic chunk count and chunk sizes;
- no random allocation pattern during timed measurement;
- exact total payload sizes:
  - 1 KiB;
  - 64 KiB;
  - 1 MiB;
- at least one multi-frame case for every payload rather than `Full<Bytes>`;
- optional controlled producer delay as a separate slow-producer case, not mixed into the throughput case;
- request trailers only as a separate capability case if measured at all.

Legacy adapter:

- use `create_upstream_streaming_client` or the exact legacy production-equivalent generic client;
- issue through `send_request_streaming_generic` with the common Body;
- consume the response body incrementally.

Eggfetch adapter:

- use the qualified `EggfetchUpstreamClient`;
- issue through `execute<B>` with the same common Body;
- consume `NativeResponseBody` incrementally using the same response-drain logic/measurement boundary.

Do not time body construction on one side but exclude it on the other.

### Response workload equivalence

For each streaming request workload the loopback server must emit the same:

- status;
- headers;
- response byte count;
- frame/chunk pattern where practical;
- protocol version;
- connection behavior.

Measurement ends at the same semantic point on both sides: full response body consumed, unless the workload explicitly measures time-to-headers or early drop.

## Workstream C — Replace assumed-dead-port tests with fixture-controlled I/O proof

Remove Phase 62 tests that infer policy behavior by connecting to `127.0.0.1:9`.

Port 9 is conventionally Discard and cannot be assumed unused on every test host.

Use hermetic fixtures.

### Strict-policy no-I/O proof

Preferred pattern:

1. bind a loopback `TcpListener` to port 0;
2. retain the listener for the duration of the test;
3. run a small accept watcher/hit counter;
4. send an `http://` request through the strict lane;
5. assert the plaintext policy error occurs;
6. assert accept count remains zero.

### Plaintext-capable I/O proof

Against the same kind of fixture:

1. bind loopback port 0;
2. accept one connection and either:
   - return a minimal HTTP response, or
   - deliberately close after accept;
3. send through the plaintext-capable lane;
4. assert the accept counter becomes one;
5. assert any resulting error is after the policy gate, not the plaintext policy rejection.

Apply this to both:

- `crates/synvoid-proxy/src/client_registry.rs` ordering tests;
- `crates/synvoid-http/tests/eggfetch_registry_policy_separation.rs`.

Keep the invalid-CA no-I/O listener test hermetic as well.

## Workstream D — Re-run the primary small-request workloads with enough evidence

The Phase 62 closeout recorded:

- legacy concurrent small: ~50,000 rps, p95 212 µs, p99 572 µs;
- eggfetch concurrent small: ~40,000 rps on both recorded after-runs, p95 648–854 µs, p99 999–1231 µs.

That is too large to dismiss solely because another workload was noisy.

Requalify these workloads with a measurement protocol designed to distinguish host noise from a persistent transport delta.

Required cases:

1. H1 keepalive, sequential small request;
2. H1 concurrent small request;
3. H2 multiplexed small request;
4. streaming 1 KiB;
5. streaming 64 KiB;
6. streaming 1 MiB;
7. concurrent streaming;
8. early response-body drop + recovery.

Cold construction may remain informational/non-hot-path.

### Run protocol

On one host, one architecture, one toolchain:

- build both revisions before timed runs;
- warm each workload before samples;
- run at least 5 independent measured repetitions per revision/workload;
- each primary small-request repetition should be long enough to avoid single-digit-millisecond quantization; target >=5 seconds steady-state or enough requests to exceed that duration;
- alternate revision order (ABBA / BAAB or randomized deterministic schedule) rather than running all baseline first and all current second;
- record each repetition independently, not only an aggregate;
- avoid other heavy local workloads;
- record thermal/power mode where accessible;
- use the same compiler target architecture for both revisions.

If running on Apple Silicon, prefer native arm64 rather than Rosetta. If Rosetta is unavoidable, both revisions must use the exact same target and the record must say so.

Do not compare a macOS result numerically to a Linux result. A Linux target-class run is useful follow-up evidence but must be presented as a separate dataset.

### Metrics

For each measured workload record:

- request count;
- wall-clock duration;
- throughput;
- latency p50;
- latency p95;
- latency p99;
- failures/timeouts;
- bytes transferred;
- protocol/version;
- concurrency;
- payload/chunk geometry.

Report per-run values plus median and spread across runs.

## Workstream E — Statistical/adjudication rule

Preserve the campaign's >5% material-regression rule, but apply it to reproducible central estimates rather than one short run.

A primary workload is **clear** when:

- median throughput regression is <=5%, and
- p95/p99 do not show a repeatable material increase outside measured run-to-run spread.

A primary workload is **material** when a >5% throughput or meaningful tail-latency regression persists across the repeated same-workload measurements.

Do not claim "noise" merely because:

- another workload varied;
- one favorable rerun exists;
- absolute loopback durations are small.

If the result is ambiguous, increase sample duration/repetitions before changing runtime code.

## Workstream F — Profile only persistent regressions

If H1/H2 small-request or streaming results remain materially worse after Workstreams B-D, profile the current eggfetch lane against the legacy baseline.

Investigate measured sources, not speculative redesign.

Likely observation points include:

- eggfetch request admission / logical pool bookkeeping;
- client/cache lookup placement;
- request/response body adaptation;
- `SyncBody` mutex polling on response paths;
- extra allocations or boxed futures;
- H1 connection reuse;
- H2 stream admission/multiplexing;
- timeout wrapper placement;
- response collection/drain logic in the benchmark itself.

Use the platform-appropriate profiler:

- Linux: `perf`, samply, or equivalent;
- macOS: Instruments / sample / samply.

Record flamegraph/profile artifacts or a concise textual summary under the benchmark results directory.

### Corrective implementation threshold

Only make runtime performance changes when a profile identifies a specific avoidable cost.

Any optimization must preserve:

- explicit aws-lc provider selection;
- chain/hostname/SNI/custom-CA semantics;
- policy-aware registry separation;
- fail-before-I/O invalid-policy behavior;
- streaming/frame/trailer semantics;
- timeout behavior;
- compatibility aliases/signatures;
- no migration of higher-level policy into eggfetch.

If the persistent cost is inside eggfetch itself and cannot be corrected cleanly in SynVoid without duplicating transport ownership, record that fact and open/track a general upstream eggfetch improvement rather than introducing a SynVoid-specific fork.

A persistent >5% primary-path regression may be accepted only if it is:

- reproduced;
- profiled/explained;
- quantitatively documented;
- operationally adjudicated against the maintenance/security benefit;
- explicitly labeled as an accepted residual rather than called parity.

If no such adjudication is made, leave the campaign evidence-open.

## Workstream G — Keep benchmark artifacts reviewable

Commit:

- harness source;
- runner script;
- README;
- raw result files used for final adjudication;
- summarized dated result document.

Do not commit Criterion HTML directories, target artifacts, profiler caches, or huge raw traces.

The README must explain:

- manual invocation;
- immutable worktree overlay model;
- supported host assumptions;
- result format;
- how to reproduce a named result file;
- why the benchmark is not CI;
- how to add a new dated result without overwriting history.

If a result document is regenerated, never silently replace prior evidence. Add a new dated/identified result.

## Workstream H — Verification after any runtime/test/harness changes

At minimum:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http-client -p synvoid-proxy -p synvoid-http -p synvoid-http3 -p synvoid-upstream --cargo-profile ci --profile ci
cargo xtask test guards
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo deny check
cargo audit
cargo xtask verify
```

If any production transport code changes as a result of profiling, also rerun:

```bash
cargo xtask verify-full
cargo xtask verify-release
```

If the only implementation changes are benchmark/test/docs hygiene and no runtime source changes after `c3568ef4`, the already-recorded Phase 62 full/release run may remain the runtime qualification, but the final record must say exactly which proof-bearing runtime SHA those commands covered. Do not imply they ran on a later docs-only tree if they did not.

## Workstream I — Correct documentation residue

Correct the small current-state inconsistencies:

1. In `plans/roadmap.md`, change the campaign heading from:
   `Eggfetch 0.2 Transport Consolidation — Active`
   to a Phase-63-truthful state while this handoff is active, then to `Closed` only after final evidence passes.

2. In `src/http_client/AGENTS.override.md`, remove the duplicated:
   `Production egress uses synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient`
   bullet while preserving the policy-aware registry and facade rules.

3. Update the HTTP-client skill only if the benchmark/performance result changes current operational guidance.

4. Preserve Phase 61 and Phase 62 records as historical evidence. Do not rewrite their original measurements; add supersession pointers where necessary.

## Workstream J — Final evidence record

Create:

`architecture/eggfetch_0_2_transport_performance_requalification.md`

It must record:

- why Phase 63 reopened evidence;
- runtime SHA under test;
- immutable legacy SHA;
- benchmark harness commit SHA;
- adapter hashes;
- exact host/toolchain/target;
- true streaming method on each revision;
- exact workload matrix;
- run-order protocol;
- all repetition results or links to committed raw files;
- aggregate/median/spread;
- any profiler result;
- any runtime optimization made and its proof-bearing SHA;
- verification commands;
- final performance adjudication.

Then amend:

- `architecture/eggfetch_0_2_transport_corrective_closeout.md`;
- `plans/phase_62_eggfetch_policy_keying_and_evidence_corrective_closeout.md`;
- `plans/eggfetch_0_2_transport_consolidation_roadmap.md`;
- `plans/roadmap.md`;
- this Phase 63 plan.

The Phase 62 document should remain authoritative for the runtime policy/TLS correction. Phase 63 becomes final authority only for performance/reproducibility evidence and final campaign closure.

## Required test changes

Before Phase 63 can close:

- no policy-isolation test depends on `127.0.0.1:9` being closed;
- strict-policy tests prove zero fixture connections;
- plaintext-capable tests prove the request passed the policy gate via a fixture connection;
- true streaming benchmark body is multi-frame on both revisions;
- benchmark script validates the requested revision SHA before each run;
- benchmark script refuses a dirty production worktree unless explicitly run in a disposable worktree mode.

## Acceptance criteria

Phase 63 is complete only when:

- benchmark source and execution tooling are committed and reviewable;
- the legacy and eggfetch streaming measurements use equivalent multi-frame streaming bodies and equivalent response consumption;
- no result labeled "streaming comparison" uses a buffered baseline path;
- H1 sequential, H1 concurrent, H2 multiplexed, and streaming primary workloads have >=5 meaningful repeated measurements per revision on the same host/target;
- small-request measurements are long enough to avoid the previous millisecond-scale quantization problem;
- the previously observed ~20% concurrent-small throughput/tail delta is either:
  - no longer reproduced under the stronger protocol, or
  - reproduced and profiled/explained, with a corrective optimization and rerun where appropriate, or
  - explicitly accepted/documented as a quantified residual rather than called parity;
- all policy-isolation tests use fixture-controlled network behavior;
- production security/API/streaming invariants remain unchanged;
- final benchmark raw data and metadata are committed;
- current docs no longer say both "Active" and "closed";
- duplicate AGENTS guidance is removed;
- the final evidence record truthfully identifies the runtime proof-bearing SHA and benchmark harness SHA;
- no unexplained >5% regression is hidden behind a generic "noise" statement.

## Rejection criteria

Reject Phase 63 closure if it:

- compares eggfetch streaming against legacy buffered POST;
- keeps the harness source outside the repo and records only hashes;
- uses single-digit-millisecond aggregate runs as primary throughput evidence;
- declares a repeatable 20% delta "noise" without same-workload repeated evidence;
- optimizes runtime code before demonstrating/profile-confirming the regression;
- weakens TLS, policy isolation, failure semantics, or streaming correctness for performance;
- benchmarks different hosts/architectures and presents the numbers as direct before/after;
- reintroduces legacy Hyper as a production lane;
- turns manual performance measurements into unstable routine CI gates;
- rewrites Phase 62 runtime history instead of superseding only its performance-evidence conclusion.

## Expected terminal state

The expected final state remains:

- eggfetch is the sole production generic egress transport;
- Phase 62 policy/TLS corrections remain intact;
- legacy Hyper transport remains frozen compatibility-only;
- transport benchmark methodology is reproducible from the repository;
- true streaming performance is compared apples-to-apples;
- small-request concurrency performance is honestly adjudicated;
- Phases 58-63 form a coherent closed campaign.

If requalification reveals a persistent material regression, the implementation may still remain adopted while a narrowly scoped performance residual/upstream issue stays open, but the documentation must say exactly that rather than claiming unqualified parity.
