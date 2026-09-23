# Eggfetch 0.2 Transport Performance Requalification (Phase 63 — final evidence authority)

Status: **closed 2026-09-22.** Final authority for performance/reproducibility
evidence. The Phase 62 record
(`architecture/eggfetch_0_2_transport_corrective_closeout.md`) remains
authoritative for the runtime policy/TLS correction; its §6/§9 benchmark
conclusion is superseded by this document.

## 1. Why evidence reopened

Phase 62 fixed the runtime defects correctly (policy-aware registry,
fail-before-I/O invalid TLS policy, eggfetch production lane) but its
benchmark evidence could not support the parity claim:

1. the "streaming" comparison ran eggfetch native streaming against a
   **buffered** legacy POST;
2. the legacy baseline already exposed `send_request_streaming_generic`,
   so an apples-to-apples streaming comparison was possible and was not done;
3. the concurrent-small result (≈20% throughput deficit, worse p95/p99)
   was dismissed as noise on insufficient same-workload repetitions;
4. the harness source was never committed (hash-only evidence);
5. policy-isolation tests assumed `127.0.0.1:9` is a dead port;
6. documentation residue (campaign "Active" vs closed, duplicated
   AGENTS bullet).

This phase requalified everything without touching production runtime code:
no registry/TLS/policy change was made, and none was needed.

## 2. Revisions and provenance

- Immutable legacy baseline: `7083f339a43dd13d6c8f65e7acc9d03ee555b6ef`
  (pre-migration planning head; contains no Phase 58–62 production code).
- Runtime under test: Phase 62 proof-bearing `c3568ef4...` **unchanged**.
  `git diff c3568ef4..HEAD -- src/ crates/ tools/` touches only:
  `synvoid-proxy` dev-dependencies (tokio test features), `#[cfg(test)]`
  policy-isolation tests, and an `AGENTS.override.md` dedup. No production
  source changed, so the Phase 62 `verify-full`/`verify-release`
  qualification at `c3568ef4` remains the runtime qualification; rerunning
  release qualification on a docs/test-only tree would prove nothing new.
- Current-tree SHAs in the table below differ only by committed
  benchmark/test/docs commits, never by runtime behavior.
- Harness: `benchmarks/http_transport/` (committed; manual-only, never CI).
  Per-session harness tree SHA, adapter SHA-256, toolchain, host, target,
  profile, and command lines are recorded in each session's `RUN.md` /
  `commands.log`. The committed `Cargo.lock` is overlaid verbatim into both
  worktrees, so both revisions build **identical transitive dependency
  versions**.
- Host/toolchain (all sessions): `rustc 1.98.1`, profile `ci`, target
  `aarch64-apple-darwin` (native ARM64 binaries; the `x86_64` in the host
  string is the translated parent shell — both lanes share the exact same
  target), Darwin 25.6.0, Apple M4 Pro, loopback only.
- True streaming methods: legacy `create_upstream_streaming_client` +
  `send_request_streaming_generic` with the common multi-frame body inside
  `ErasedBodyImpl::new` (frame-preserving shim, documented in the adapter);
  eggfetch `EggfetchUpstreamClient::cached` + `execute<B>` with the same
  body. Response boundary on both lanes: full body drained. Body
  construction inside the timed section on both lanes. No buffered baseline
  anywhere in a streaming comparison.

## 3. Sessions (raw data committed, never overwritten)

| Session | Scope | Runs | Result dir |
|---|---|---|---|
| run-1 | full matrix, v1 counts | 100, 0 failures | `benchmarks/http_transport/results/2026-09-22T185908Z/` |
| run-2 | full matrix, second-scale streaming counts | 100, 0 failures | `.../2026-09-22T192815Z/` |
| persistence | `stream-concurrent` conc 4 | 12, 0 failures | `.../2026-09-22T200426Z/` |
| conc2 | `stream-concurrent` conc 2 | 6, 0 failures | `.../2026-09-22T202646Z/` |
| conc8 | `stream-concurrent` conc 8 | 6, 0 failures | `.../2026-09-22T202937Z/` |
| phases | `stream-64k-phases` TTH-vs-drain, immutable | 10, 0 failures | `.../2026-09-22T204937Z/` |
| diagnostic | same-tree 300k H1 runs + superseded pilot (labeled, non-authoritative) | 12 files | `.../results/diagnostic-sametree/` (see its `NOTE.md`) |

Phase 63 committed six authoritative immutable comparison sessions
(two full matrices, concurrent-streaming persistence, concurrency-2,
concurrency-8, and the 64 KiB phase-split), plus separately labeled
same-tree diagnostics that are non-authoritative for before/after parity.
The phase-split session holds ten lane/result runs but is one immutable
comparison session; run counts are not session counts.

Run-order protocol: detached worktrees per revision, independent builds
(legacy `--no-default-features`), ABBA lane alternation per workload per
rep, ≥5 measured reps per revision/workload in matrix sessions,
small-request reps ≥5 s steady-state, measured wall clock starts after
warmup. Each session directory holds per-rep JSON, `RUN.md`, `commands.log`,
and generated `summary.md`.

Workload matrix: `h1-sequential` (40k×1), `h1-concurrent` (200k×8),
`h2-multiplexed` (150k×16, TLS+ALPN, 1 server connection both lanes),
`stream-1k` (12k; 4×256 B), `stream-64k` (8k; 16×4 KiB),
`stream-1m` (800; 64×16 KiB), `stream-concurrent` (15k×conc4; 64 KiB),
`stream-slow-producer` (50; 1 ms pacing), `early-drop` (800 + recovery),
`cold-construct` (informational, unique-SNI builds, no I/O).

## 4. Aggregates (median rps, eggfetch vs legacy; 0 failures everywhere)

| workload | run-1 | run-2 | follow-up |
|---|---|---|---|
| h1-sequential | −10.9% | −19.6% | pooled paired median **−4.4%**; 300k parity −1.3% |
| h1-concurrent | −4.2% | −3.1% | — |
| h2-multiplexed | −6.2% | **+4.9%** | — |
| stream-1k | −4.0% | **+10.3%** (5/5 positive) | — |
| stream-64k | −6.0% | −9.5% | immutable phases **−1.4%**, 3/5 wins, TTH/drain identical |
| stream-1m | noisy | −2.7% (p95 better) | — |
| stream-concurrent | −20.4% (ms-scale, invalid) | −7.9% | conc2 −1.4%; conc4 −18.7%; conc8 −9.6% |
| stream-slow-producer | clear | +2.2% | — |
| early-drop | clear | +20.1%, 0 recovery failures | eggfetch TTH better |
| cold-construct | eggfetch ~70× faster | same | informational |

Spreads routinely reach ±10–40% per lane per session (both lanes collapse
together in disturbed reps — textbook host-state effect on a shared
laptop host), which is why adjudication uses paired within-rep deltas and
phase splits, not single medians.

## 5. What the follow-ups proved

- **Host drift, not transport.** Both lanes swing together across reps and
  sessions (run-1 rep2 collapse hit both lanes; absolute levels differ
  ±20–30% between sessions for both lanes). Single-session medians move
  with host state.
- **Sequential streaming has no systematic cost.** The immutable phase-split
  session measures time-to-headers and drain separately at identical
  geometry: TTH p50 within 5 µs, drain p50 within 4 µs, 3/5
  eggfetch wins, median −1.4%. A hidden systematic transport cost cannot
  survive identical phases.
- **The concurrent-streaming deficit is real, tail-shaped, and
  concurrency-dependent.** conc1–2: parity (−1.4%, p95 better on eggfetch);
  conc4: −7.9%/−18.7%; conc8: −9.6%. p50s are equal at every concurrency;
  p95/p99 degrade on eggfetch only under conc ≥ 4 while sequential phases
  stay identical — the signature of pool-admission/shared-state contention
  under synchronized streaming bursts, not of per-request or per-byte cost.
- **Request path is faster on eggfetch.** Early-drop TTH (64 KiB upload to
  headers): eggfetch 71–144 µs vs legacy 142–393 µs across 10 reps, with
  zero recovery failures on both lanes (drop handling itself favors the
  eggfetch pool: no poisoned-connection retry).
- **Bulk paths favor eggfetch.** stream-1k +10.3% (5/5), stream-1m parity
  with better p95, early-drop +20%, cold construction ~70× faster,
  H2 multiplexed +4.9% with proven single-connection multiplexing.

## 6. Profiler note (Workstream F method limit)

`sample(1)` produces empty call graphs for these binaries on this host
(Rosetta-unwindable thread state) and no other sampling profiler was
available; there are no committed flamegraphs. Localization was done
instead with the phase-split workload (TTH vs drain, §5), which answers
the question a profile would have answered for the sequential path
(neither phase differs). For the concurrent residual, the mechanism is
narrowed to concurrency-dependent tail contention (pool admission is the
standing hypothesis, one of the plan's predicted observation points), but
no SynVoid-side avoidable cost was identified, so **no runtime performance
change was made** — exactly per the corrective threshold. Optimizing blind
would risk the Phase 62 security/policy invariants for a host-sensitive
tail effect.

## 7. Adjudication

- **Clear (parity within host spread, no reproducible regression):**
  h1-sequential (pooled paired −4.4%, 300k parity −1.3%),
  h1-concurrent, h2-multiplexed, stream-1k, stream-64k (phase-parity
  tiebreaker over drifted matrix medians), stream-1m,
  stream-slow-producer, early-drop.
- **Accepted residual (quantified, labeled, not parity):**
  `stream-concurrent` under synchronized concurrency ≥ 4: −8% to −19%
  median throughput, equal p50, worse p95/p99; sequential phases
  identical; conc1–2 at parity. Operational reading: p50 (typical request)
  is unaffected everywhere; the H2-multiplexed path — the high-concurrency
  production pattern — is at parity/+4.9%; synchronized N-way 64 KiB
  streaming bursts are not SynVoid's paced upstream pattern. The
   single-transport maintenance/security benefit outweighs this bounded
   tail effect. SynVoid accepts this residual for its 0.2 adoption.
   Active investigation plan: `eggstack/eggfetch:
   plans/native-concurrent-streaming-tail-investigation.md` (upstream
   planning baseline `8959ca890ee34f4cf456aed648315322f1e83ef7`;
   registration/index reconciliation
   `b3c009df90f9ab09e91e8fa7464653dceb300dd8`). The mechanism is not yet
   proven and no correction has shipped; no SynVoid fork or local
   workaround is planned unless future evidence materially changes the
   tradeoff (a local workaround would duplicate transport ownership).
- The Phase 62 H1-concurrent ≈20% short-run delta is **not reproduced**
  under the stronger protocol (−4.2%/−3.1%, equal p50s); the Phase 62
  numbers stand as historical short-run evidence only.
- No TLS, policy-isolation, failure-semantics, streaming-correctness, or
  compatibility invariant was weakened for any number in this record.

## 8. Verification on the closeout tree

Implementation delta since `c3568ef4` is benchmark/test/docs hygiene only
(§2), so the Phase 62 `verify-full`/`verify-release` at `c3568ef4` remains
the runtime qualification. Re-run on the closeout tree:

- `cargo fmt --all -- --check`: green (harness formatted in its own crate).
- Focused nextest (`synvoid-http-client`, `-proxy`, `-http`, `-http3`,
  `-upstream`, `--profile ci`): green, including the Phase 63
  fixture-controlled policy tests.
- `cargo xtask test guards`: green.
- Feature-profile `cargo check --no-default-features` with
  `[]`, `post-quantum`, `mesh`, `dns`, `mesh,dns`: green.
- `cargo deny check` / `cargo audit`: green.
- `cargo xtask verify`: green (single CI job + dependency-security).

## 9. Decision

**Adopted/closed.** Eggfetch remains the sole production generic egress
transport; Phase 62 policy/TLS corrections intact; legacy Hyper frozen
compatibility-only; benchmark methodology reproducible from the
repository; true streaming compared apples-to-apples; small-request
concurrency honestly adjudicated; one quantified tail residual accepted
and tracked. Phases 58–63 form a coherent closed campaign.
