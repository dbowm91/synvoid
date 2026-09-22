# HTTP transport comparison harness (Phase 63, manual-only)

Reproducible, apples-to-apples transport evidence for the eggfetch 0.2
campaign. Compares the immutable pre-migration Hyper lane
(`7083f339...`) against the current eggfetch lane on one host, one
toolchain, one build profile.

**This harness is never a CI gate.** Transport loopback numbers are
host-sensitive by nature; routine CI must stay deterministic. Run it by
hand when transport evidence is needed, and commit each new dated result
without overwriting history.

## Layout

```text
benchmarks/http_transport/
    README.md            # this file
    Cargo.toml           # detached crate ([workspace]); features: eggfetch (default)
    Cargo.lock           # pinned transitive deps; overlaid verbatim so both
                         # revisions build identical dependency versions
    src/
        main.rs          # CLI driver: one workload × one lane → one JSON result
        common.rs        # shared fixture body, loopback servers, stats, envelope
    adapters/
        legacy_7083f339.rs   # legacy Hyper lane (frozen API; compiles old AND new tree)
        eggfetch_current.rs  # eggfetch lane (compiled only with `eggfetch` feature)
    certs/
        test-only-loopback-*.pem/key  # loopback-only TLS fixtures (see below)
    scripts/
        run_comparison.sh    # immutable-worktree overlay + ABBA matrix runner
    results/
        <stamp>/             # one directory per full comparison run
```

## Invariants

- Common workload generation and measurement code is shared (`src/common.rs`).
- Lane differences are isolated to the two small adapter modules.
- The exact adapter source used for each revision is committed; per-run
  SHA-256 of the used adapter is recorded in every result file.
- Results are machine-readable JSON plus a generated Markdown summary.
- The old runtime revision stays immutable: only committed
  benchmark-only files are overlaid into its worktree. Production source
  is never patched to make a baseline easier to benchmark.

## True streaming equivalence (Workstream B)

Both lanes send the same deterministic multi-frame body
(`FixtureBody`: 1 KiB in 4×256 B, 64 KiB in 16×4 KiB, 1 MiB in 64×16 KiB —
never `Full<Bytes>`), which satisfies the stricter legacy bounds
(`Send + Sync + Unpin + 'static`) so the shape is identical:

- legacy: `create_upstream_streaming_client` +
  `send_request_streaming_generic` (the exact production-equivalent generic
  entry point; the common body travels inside `ErasedBodyImpl::new`, which
  preserves the frame sequence without buffering — documented shim);
- eggfetch: qualified `EggfetchUpstreamClient::cached` + `execute<B>` with
  the same body.

Response consumption ends at the same semantic point on both sides: the
full response body is drained (`drain_body`; the shared helper polls to
completion). Request-body construction happens inside the timed section on
both lanes. The loopback server emits identical status/headers/byte counts
for both lanes and cannot tell which lane is calling.

A buffered POST is never used as the legacy side of a streaming
comparison.

## Workloads

| workload | protocol | geometry |
|---|---|---|
| `h1-sequential` | H1 keepalive, plaintext loopback | small GET, conc 1 |
| `h1-concurrent` | H1, plaintext loopback | small GET, conc 8 |
| `h2-multiplexed` | H2 over TLS+ALPN loopback | small GET, conc 16, 1 connection expected |
| `stream-1k` / `stream-64k` / `stream-1m` | H1 streaming POST | multi-frame bodies above |
| `stream-concurrent` | H1 streaming POST | 64 KiB, conc 4 |
| `stream-slow-producer` | H1 streaming POST | 64 KiB, 1 ms pacing per frame (diagnostic) |
| `early-drop` | H1 streaming | headers received, body dropped, recovery GET |
| `cold-construct` | none (no I/O) | unique-SNI client builds (informational) |

Small-request repetitions target ≥5 s steady-state each; the measured wall
clock starts after warmup in every runner.

## Loopback TLS fixtures

`certs/` holds a test-only CA plus a leaf certificate/key for
`localhost` / `127.0.0.1`, used solely by the in-process H2 loopback
server and its two lane clients. The private keys are **test-only
loopback fixtures, not credentials**: they sign nothing outside
`127.0.0.1`, expire 2028-12, and are regenerated with:

```bash
# (from certs/)
openssl req -x509 -newkey rsa:2048 -keyout test-only-loopback-ca.key \
  -out test-only-loopback-ca.pem -days 3650 -nodes -subj "/CN=synvoid-bench-test-only-loopback-ca"
openssl req -newkey rsa:2048 -keyout test-only-loopback-leaf.key \
  -out leaf.csr -nodes -subj "/CN=localhost"
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > san.ext
openssl x509 -req -in leaf.csr -CA test-only-loopback-ca.pem \
  -CAkey test-only-loopback-ca.key -CAcreateserial \
  -out test-only-loopback-leaf.pem -days 825 -extfile san.ext
```

## Manual invocation

Full immutable comparison (5 reps × 10 workloads × 2 lanes, ABBA order):

```bash
./benchmarks/http_transport/scripts/run_comparison.sh
```

Useful flags: `--reps N`, `--profile ci|release`,
`--legacy-rev SHA`, `--current-rev REV` (default `HEAD`),
`--out DIR`, `--keep-worktrees`, `--smoke` (tiny pipeline test only —
smoke numbers are never adjudication evidence), `--workloads "w1 w2"`
(subset for focused follow-ups), `--extra-args "--concurrency 8"`
(diagnostic overrides, recorded verbatim in `commands.log`).

Single workload on one lane (uses in-tree harness build):

```bash
cargo build --profile ci --manifest-path benchmarks/http_transport/Cargo.toml
BENCH_REVISION_SHA=... BENCH_HARNESS_SHA=... BENCH_ADAPTER_SHA=... \
BENCH_TOOLCHAIN="$(rustc -V)" BENCH_HOST="$(uname -smr)" \
BENCH_PROFILE=ci BENCH_TARGET="$(rustc -vV | grep host | cut -d' ' -f2)" \
./benchmarks/http_transport/target/ci/http-transport-bench \
  --lane eggfetch --workload h1-sequential \
  --certs benchmarks/http_transport/certs --out /tmp/run.json
```

Aggregate a set of result files:

```bash
./benchmarks/http_transport/target/ci/http-transport-bench \
  summarize results/<stamp>/rep*-*.json --out results/<stamp>/summary.md
```

## Immutable worktree overlay model

`run_comparison.sh` verifies a clean tree, creates detached worktrees for
the legacy and current revisions, copies **only** `Cargo.toml`,
`Cargo.lock`, `src/`, `adapters/`, `certs/` into each worktree, builds each
independently
(legacy with `--no-default-features`, which drops the eggfetch adapter),
then runs the matrix alternating lanes per workload per rep. Recorded per
run: source revision SHA, harness tree SHA, adapter file SHA-256, common
harness SHA-256, rustc/cargo version, host OS/kernel/arch/CPU, build
profile, target, and command line. Temporary worktrees are removed unless
`--keep-worktrees` is passed.

Host assumptions: loopback networking, no heavy co-tenant load during
timed runs, native arch preferred (Rosetta is allowed only if both lanes
use the exact same target — and the record must say so). Never compare
numbers across hosts/architectures as before/after evidence.

## Adding a new dated result

Run the script, keep the generated `results/<stamp>/` directory
(`RUN.md`, `commands.log`, per-rep JSON, `summary.md`), and reference it
from the evidence record
(`architecture/eggfetch_0_2_transport_performance_requalification.md`).
Never silently replace a prior result directory.
