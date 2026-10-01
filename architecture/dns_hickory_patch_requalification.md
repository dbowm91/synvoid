# Hickory 0.26.3 Patch Requalification

Status: **CLOSED QUALIFIED** (2026-10-01).

Baseline: `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).
Proof-bearing implementation SHA: `857d2e76dd453dc9dd0c84aa89bc1293cc8a1e1b`.
Exact-SHA hosted CI and dependency-security: [run 36922488692](https://github.com/dbowm91/synvoid/actions/runs/36922488692), passed.

## Dependency change

The production DNS graph resolved `hickory-proto`, `hickory-net`, and
`hickory-resolver` at 0.26.1 before this phase. The targeted lockfile update
moves all three to 0.26.3. No Hickory source fork, git dependency, manifest
range change, or unrelated registry refresh was introduced.

The upstream 0.26.2 release addresses a broad group of DNSSEC-validation,
denial-of-service/resource-consumption, parser-panic, UDP-spoofing, cache, and
protocol-correctness issues. The 0.26.3 release fixes regressions from 0.26.2,
including DNSSEC verification, QUIC/HTTP3 server behavior, minimum dependency
versions, and insecure-ancestor delegation. Phase 108 must use 0.26.3 as its
comparison baseline. References: [0.26.2 release](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.2),
[0.26.3 release](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3).

## Lockfile delta

The Hickory family moved atomically to 0.26.3. The release's minimum dependency
updates also changed the selected `windows-sys` from 0.60.2 to 0.61.2 and moved
three existing consumers of `socket2` from 0.6.4 to 0.5.10. No other Hickory
versions or crypto-provider features changed; DNSSEC remains enabled through
`dnssec-ring`, and resolver `recursor` remains enabled. `ring`/aws-lc-rs
features were not changed by this phase.

## Local qualification

- `cargo test -p synvoid-dns --profile ci`: passed (589 unit tests and all
  package integration suites).
- `cargo test -p synvoid-dns --profile ci --features mesh`: passed (1,274
  tests across 37 suites; 15.32s test execution).
- `cargo check --no-default-features --features dns --profile ci`: passed
  (715 crates; 27 existing warnings).
- `cargo check --no-default-features --features mesh,dns --profile ci`: passed
  (10 crates checked; 27 existing warnings).
- `cargo deny check`: passed (existing duplicate-version diagnostics only).
- `cargo audit`: no vulnerability failure; six allowed unmaintained-crate
  warnings (RUSTSEC-2023-0089, RUSTSEC-2025-0141 twice,
  RUSTSEC-2025-0057, RUSTSEC-2024-0370, RUSTSEC-2026-0173).
- `cargo fmt --all -- --check`: passed.
- `cargo xtask verify`: passed all 10 steps after rerunning with
  `PKG_CONFIG_PATH=/usr/local/opt/xz/lib/pkgconfig` to select the machine's
  x86_64 Homebrew liblzma instead of the arm64 MacPorts library.
- `cargo xtask verify-full`: passed all 10 steps, including the supported
  feature-profile matrix, 7,891 workspace tests (8 skipped by policy), and
  workspace doctests.

## Bounded performance comparison

All five prescribed Criterion benches were run on the same host and toolchain
against the pre-update baseline (`19c0636535f3728e80b7c6777ec6a552c38c61a0`)
and the updated Hickory lockfile. Each invocation used 10 samples, 1s
measurement, and 0.1s warmup per case. Host: x86_64 macOS; Rust 1.98.1
(`x86_64-apple-darwin`). Gnuplot was unavailable, so Criterion used Plotters.

Criterion detected no statistically significant change for most cases and
reported improvements in several cache, parser, zone, coalescer, and limit
cases. No repeatable material regression appeared. These short, single-host
samples are a sanity check only; observed improvements, especially sub-
nanosecond limit checks, are treated as run noise and not claimed as product
gains.

## Formal closure

Phase 105 is CLOSED QUALIFIED. The qualified baseline, lockfile delta, local
verification, benchmark evidence, and accepted measurement limits are recorded
above. Exact-SHA hosted CI and dependency-security both passed on the
proof-bearing implementation SHA.
