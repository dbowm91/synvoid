# Track 3 Performance Report

Status: Phase 24 closure baseline. Establishes representative hot-path medians
after the Track 3 ownership convergence (Phases 17–23) and records the
benchmark consolidation performed in this phase.

Non-goals: microbenchmarks are regression indicators only. This report makes
no absolute throughput claims (no "1M RPS" style statements); end-to-end
request throughput depends on I/O, TLS, upstream, and deployment topology,
none of which microbenchmarks measure.

## 1. Environment

| Item | Value |
|------|-------|
| Host | Apple M4 Pro, Darwin 25.6.0 (x86_64 build) |
| Toolchain | rustc 1.98.1, cargo 1.98.1 |
| Revision | `ca7b20ac` + Phase 24 working tree |
| Profile | `--profile ci` (dev + `opt-level = 1`, matches routine CI test profile) |
| Criterion | 0.5, `--measurement-time 2 --warm-up-time 1 --sample-size 10` for new groups |

CI hosts are heterogeneous; do not gate routine CI on these absolute
numbers. Re-run locally with the commands below and compare against your
own machine's baseline.

## 2. Hot-path to benchmark map

| Track 3 hot path | Benchmark group | Binary |
|------------------|-----------------|--------|
| Benign request parse/normalization | `normalize/benign`, `normalize/small_request`, `normalize/with_body`, `normalize/large_body` | `bench_normalization` |
| Encoded/adversarial normalization | `normalize/encoded`, `normalizer` attack inputs | `bench_normalization`, `bench_attack_detection_wave10` |
| WAF allow/no-match path | `attack_detection` benign, `attack_detection_sqli/xss` | `bench_attack_detection_wave10` |
| WAF terminal decision/reducer overhead | `enforcement_reduce/*`, `waf_adapter/*` (**new**) | `bench_attack_detection` |
| Rate-limit lookup/update | `atomic_bucket_window/*`, `sliding_limiter/*` (**new**) | `bench_ratelimit` |
| Block-store lookup/admission | `blockstore_lookup/*` (**new**) | `bench_ratelimit` |
| Proxy/forward-header construction | `forward_headers`, `extract_real_ip`, `x_forwarded_for_parsing` | `bench_proxy_headers` |
| Streaming/body-policy common path | `framing_policy/*` (**new**), `normalize/with_body`, `normalize/large_body` | `bench_normalization` |
| Jail IPC round-trip (excl. WASM exec) | `jail_ipc_roundtrip/*` (**new**) | `bench_wasm` |
| Proxy cache, DNS, broadcast, routing | `proxy_cache*`, `dns*`, `broadcast*`, `routing*` | existing binaries (unchanged) |

## 3. Representative medians (this machine, `--profile ci`)

New Phase 24 groups:

| Benchmark | Median | Note |
|-----------|--------|------|
| `enforcement_reduce/reduce_all_8_mixed` | ~72 ns | 8-claim fold incl. adapter construction |
| `enforcement_reduce/reduce_all_allow_only` | ~23 ns | Empty-ish allow path stays allocation-free |
| `waf_adapter/flood_bot_endpoint_attack` | ~2.3 ns | Per-adapter projection is branch-only |
| `sliding_limiter/check_and_increment_hot_key` | ~47 ns | Contended single key |
| `sliding_limiter/check_and_increment_sharded` | ~44 ns | 64-key shard set |
| `blockstore_lookup/is_blocked_hit` | ~197 ns | 512-entry store, global scope |
| `blockstore_lookup/is_blocked_miss` | ~94 ns | Miss is cheaper than hit (no access-time write) |
| `blockstore_lookup/block_admission_steady_state` | ~337 ns | Re-block incl. provenance + target-state record |
| `jail_ipc_roundtrip/encode_request` | ~183 ns | WasmInvoke envelope, 14-byte body |
| `jail_ipc_roundtrip/decode_request` | ~218 ns | Deserialize + envelope validation |
| `jail_ipc_roundtrip/encode_response` | ~69 ns | Pong response |
| `jail_ipc_roundtrip/decode_response` | ~25 ns | Pong response |
| `framing_policy/transfer_benign` | ~24 ns | CL-only headers |
| `framing_policy/transfer_hostile_cl_te` | ~82 ns | CL+TE ambiguity, fail-closed error path |
| `framing_policy/request_framing_benign` | ~58 ns | Transfer + host validation together |

Reproduce:

```bash
cargo bench --profile ci --bench bench_attack_detection -- --measurement-time 2 --warm-up-time 1 --sample-size 10 enforcement_reduce
cargo bench --profile ci --bench bench_ratelimit -- --measurement-time 2 --warm-up-time 1 --sample-size 10 sliding_limiter
cargo bench --profile ci --bench bench_ratelimit -- --measurement-time 2 --warm-up-time 1 --sample-size 10 blockstore_lookup
cargo bench --profile ci --bench bench_wasm -- --measurement-time 2 --warm-up-time 1 --sample-size 10 jail_ipc_roundtrip
cargo bench --profile ci --bench bench_normalization -- --measurement-time 2 --warm-up-time 1 --sample-size 10 framing_policy
```

## 4. Before/after assessment

Track 3 (Phases 17–23) moved ownership without changing hot-path
algorithms: facades are `pub use` re-exports (zero-cost), adapters are
branch-only projections, and the reducer folds `Copy` candidates with no
allocation on the allow path. No pre-refactor microbenchmark series was
recorded by earlier phases, so there is no prior median series to diff
against; the table above is the closure baseline. The convergence
introduced no new per-request copies, locks, or syscalls on the measured
paths (verified by code inspection of the facade/adapter diffs, not by
benchmark archaeology).

Regression policy: compare future runs on the same machine/profile. A
material regression is a sustained >2x median shift on any row above that
cannot be attributed to toolchain or host changes — not nanosecond noise
across heterogeneous CI hosts.

## 5. Consolidation performed (Phase 24 Part F)

- `benches/bench_attack_detection_wave10.rs`: removed stale TODO +
  commented-out `benchmark_anomaly_scoring` for the deleted
  `check_request_anomaly_scoring` API. Remaining groups use the current
  `AttackDetector::check_request` API.
- `benches/bench_attack_detection.rs`: replaced a stale toy benchmark
  (local `to_lowercase` + hand-rolled url-decode, measuring nothing in the
  engine) with the real `enforcement_reduce` / `waf_adapter` hot-path
  groups. The binary name is unchanged, so `benches/run_benchmarks.rs`
  thresholds still apply (new medians are far below the 1 ms threshold).
- `benches/bench_ratelimit.rs`: kept existing groups; added real
  `sliding_limiter` (canonical `synvoid_waf` limiter) and
  `blockstore_lookup` (canonical `BlockStore`) groups. The local toy
  `AtomicBucketWindow` groups are retained for continuity but are no longer
  the only rate-limit signal.
- `benches/bench_wasm.rs`: kept WASM fresh/pooled groups; added
  `jail_ipc_roundtrip` so jail framing cost is tracked separately from
  WASM execution cost.
- `benches/bench_normalization.rs`: kept all groups; added
  `framing_policy` for the canonical fail-closed validators.

No benchmark CI gate was added: `benches/run_benchmarks.rs` remains a
manual/local runner, per the phase constraint against machine-specific
microbenchmark gates in routine CI.

## 6. Fuzz-crash regression status

Bounded smoke runs for the three new targets completed at closure time
with no crashes and no hangs:

- `http_chunked_framing`: 300 runs, DONE (coverage 288, 37 corpus entries)
- `jail_ipc_frame_decode`: 300 runs, DONE
- `http_routing_matcher`: 300 runs, DONE (coverage 3057)

Command form (standard 1000-run smoke per
`architecture/ci_fuzz_failure_injection.md`):

```bash
cargo +nightly fuzz run http_chunked_framing -- -runs=1000
cargo +nightly fuzz run jail_ipc_frame_decode -- -runs=1000
cargo +nightly fuzz run http_routing_matcher -- -runs=1000
```

No deterministic crashes were produced, so no new crash-derived regression
tests were required beyond the hostile-input corpora already captured in
`tests/track3_invariant_closure.rs`, `tests/http_differential_closure.rs`,
and `tests/track3_concurrency_closure.rs`. Any future fuzz crash must be
converted into a normal regression test in those suites per the phase
constraint (regression tests over ongoing fuzz execution).
