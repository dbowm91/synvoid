# Eggfetch 0.2 Transport Corrective Closeout (Phase 62 — runtime corrective closed; performance evidence superseded)

> **Performance evidence reopened by Phase 63 (2026-09-22).** The Phase 62 runtime corrections remain adopted and authoritative for registry policy isolation and fail-closed TLS behavior. A later audit found that the recorded streaming benchmark compared eggfetch streaming against a buffered legacy baseline, the concurrent-small regression was not sampled deeply enough to dismiss as noise, and the harness source was not committed. Final performance/reproducibility authority moves to `plans/phase_63_eggfetch_transport_benchmark_requalification_and_final_evidence_closeout.md`. Preserve the Phase 62 measurements below as historical evidence; do not use §6/§9 as final performance-parity proof until Phase 63 closes.

## 1. Revisions

- Pre-campaign baseline: `e3026667c23e6e0e92ee30d13c53baf2e68c5c77`.
- Phase 58–60 migration: `7a6c617cf9dc16441f50da5dcff95778775b5041`.
- Phase 61 closeout attempt (reopened, historical): `f62bb285a2bdf6262efe9a7b859bc11bdcc35e15`.
- Phase 62 proof-bearing corrective implementation/qualification: `c3568ef4580a49edf222c5e4e6ce5d4dca904e81`.
- Immutable benchmark before revision: `7083f339a43dd13d6c8f65e7acc9d03ee555b6ef`
  (planning head immediately before the Phase 58–60 production migration;
  runtime equivalent to the pre-campaign baseline; contains no Phase 58–62
  production code).
- Eggfetch: `eggfetch-core =0.2.0`, features
  `native-http1, native-http2, tls-rustls, tls-native-roots`
  (no `http3`/`proxy`/`cookies`/`compression`/`json`/redirect-retry).
- Toolchain 1.98.1; profile `ci` for tests, `dev` for feature-profile
  checks, release qualification via `verify-release` (never publishes).

## 2. Policy-collision reproduction and fix

Defect (on `f62bb285`): `UpstreamClientRegistry` keyed only by `site_id`
(`DashMap<String, Arc<EggfetchUpstreamClient>>`) while callers request more
than one policy per site. `upstream_proxy_dispatch_plan.rs` requests
`allow_plaintext: true` for buffered then `UpstreamTlsConfig::default()`
(strict) for streaming; the first lookup won and the streaming lane inherited
the plaintext-capable policy despite comments claiming distinct defaults.
The inner `EggfetchUpstreamClient::cached` key was already policy-aware; the
outer site lifecycle registry was not.

Fix (on `c3568ef4`): explicit registry key
`LaneRegistryKey { site_id: String, tls_policy: UpstreamTlsConfig }`
(`crates/synvoid-proxy/src/client_registry.rs`). `UpstreamTlsConfig` already
implements `Hash + Eq` and is the canonical policy type, so no second policy
model was introduced. `skip_verify_reason` is included (conservative
fragmentation: identical transport with different audit reasons yields
distinct entries, never a collapse). Fixed registry connection settings (5s
connect / 100 idle-per-host / 30s idle) stay out of the key only while
genuinely invariant; the inner lane cache already keys them.

## 3. Registry key/invalidation design

- One entry per (site, TLS policy). The outer registry remains the site
  lifecycle/invalidation layer; eggfetch remains the physical pool owner via
  its policy-keyed global cache. No separate buffered/streaming physical
  pools were introduced; differing no-config defaults naturally resolve to
  distinct lanes.
- `invalidate(site_id)` removes every key whose `site_id` matches via
  `DashMap::retain` — O(n) over total entries, documented as acceptable
  because invalidation is configuration/control-plane frequency, never hot
  request-path.
- `clear()` remains global. Config rehash/reload flows through `invalidate`,
  so no stale policy variant stays reachable.

## 4. TLS-policy failure behavior before/after

Before: `UpstreamClientRegistry::get_or_create_lane` and
`ProxyServer::new_with_pool_config` caught lane-build failure (invalid /
missing / empty custom CA) and substituted `UpstreamTlsConfig::default()`.
A publicly trusted upstream could connect despite a broken configured custom
CA path. Logging called this "fail-closed"; it was policy substitution.

After: no substitution anywhere.

- `get_or_create_lane` returns `anyhow::Result` with site + CA-path context;
  nothing is inserted on failure.
- `prepare_upstream_proxy_dispatch_plan` returns `anyhow::Result`; the
  backend dispatcher renders the existing 502 upstream-failure response
  before any I/O.
- Streaming-WAF and H3-streaming dispatches render their existing 502 paths
  before I/O; H3-buffered propagates through its existing `BoxError` → 502
  path.
- `ProxyServer` preserves constructor signatures and stores a terminal
  `lane_init_error: Option<String>` with site/policy context. `lane_client`
  / `revalidation_lane` become `Option`; `send_single_request` fails before
  any I/O when poisoned, and SWR revalidation is skipped (stale cache served
  without background I/O). No raw usable client is exposed; no panic on
  ordinary configuration input.
- Leaf/background direct `EggfetchUpstreamClient::build` callers (geoip,
  upload feed, health, honeypot AI, granian, operator lane) already propagate
  errors (`?` / `map_err`) and use default policies that must build; audit
  confirms no silent substitution. `operator_lane_client` uses the entitled
  facade with the plaintext-allowed default only.

Black-box proof: unreadable CA path for an otherwise publicly trusted origin
yields the expected upstream/configuration failure with site context, opens
zero upstream connections (hermetic listener hit-count test), and recovery
after corrected policy + site invalidation (registry) or reconstruction
(`ProxyServer`) is test-covered.

## 5. Regression tests (all fail on `f62bb285`, green on `c3568ef4`)

`crates/synvoid-proxy/src/client_registry.rs` (6):

- buffered-first / streaming-second stay separate + strict `http://` gate
  rejects before I/O while buffered attempts I/O;
- streaming-first / buffered-second (first acquisition never sets site policy);
- distinct `ca_cert_path` / `server_name` / `skip_verify` separation
  (bad-CA material fails without inserting; reason-string variants fragment
  conservatively, documented);
- invalid CA fails closed with site context, inserts nothing;
- `invalidate(site)` removes all policy variants for one site, leaves the
  other site, next acquisition rebuilds;
- `clear()` global.

`crates/synvoid-proxy/src/server.rs` (3):

- poisoned construction stores site + CA-path context, exposes no client;
- poisoned `handle_request` renders 502 with zero upstream TCP connections
  (hermetic listener);
- corrected config reconstructs to a healthy lane (no sticky default).

`crates/synvoid-http/tests/eggfetch_registry_policy_separation.rs` (2):

- higher-level plan-order test using the exact buffered/streaming legacy
  defaults in plan order, with behavioral plaintext-gate proof;
- invalid-CA failure + cross-site isolation + invalidate recovery.

Freeze guard `eggfetch_lane_freeze_guard` remains green: production still uses
the eggfetch lane, legacy Hyper helpers stay compatibility/test-only, the
frozen `synvoid-http-client` aliases/signatures are unchanged, and retry /
failover / WAF / cache / auth / redirect / compression / tunnel / mesh policy
stay outside eggfetch. The new fallible registry API is a SynVoid composition
API, not a second transport abstraction.

## 6. Immutable benchmark methodology and results

Harness: benchmark-only test files (evidence-only, not committed to routine
CI) transplanted to two clean worktrees. Baseline worktree
(`7083f339`, no Phase 58–62 production code) runs the legacy Hyper lane;
proof-bearing tree (`c3568ef4`) runs the eggfetch lane. Same workloads, same
hermetic loopback fixtures, same iteration counts; only the transport call
differs because the baseline predates eggfetch code.

- After harness sha256:
  `0956d2722f0aa201e3a1dd64f2051728034f5b600e6975780c5f7c3229f760f7`
- Baseline harness sha256:
  `c04cbdbe4326a228198f34c5cd5e94d3032b65bcaebcf60d40a2cb32061b9288`
- Host: Darwin 25.6.0 x86_64 (Apple M4 Pro, Rosetta); toolchain 1.98.1;
  profile `ci`; loopback, no public network.
- Iterations: H1 keepalive 200 sequential; concurrent batch 8-way × 25 (200);
  streaming 1 KiB / 64 KiB / 1 MiB via `execute` (after) vs buffered POST
  (baseline) 20 each; concurrent streaming 4-way × 5 (20); early-drop 20 +
  recovery; cold construction 50 (non-hot-path).

Results (run 1; run 2 in parentheses where re-run):

| Workload | Before (legacy) | After (eggfetch) |
|---|---|---|
| H1 keepalive small | 26 ms, 7692 rps, p50 77 µs / p95 264 / p99 1178 | 31 ms (28), 6451 (7142) rps, p50 64 (76) / p95 399 (224) / p99 1815 (1653) |
| Concurrent batch | 4 ms, 50000 rps, p50 146 / p95 212 / p99 572 | 5 ms (5), 40000 (40000) rps, p50 138 (147) / p95 854 (648) / p99 999 (1231) |
| Stream 1 KiB | 4 ms, 5000 rps, p50 167 / p95 546 / p99 1447 | 1 ms (1), 20000 (20000) rps, p50 85 (66) / p95 104 (222) / p99 215 (231) |
| Stream 64 KiB | 2 ms, 10000 rps | 2 ms (2), 10000 (10000) rps |
| Stream 1 MiB | 11 ms, 1818 rps, p50 357 / p95 910 / p99 2874 | 8 ms (11), 2500 (1818) rps, p50 389 (365) / p95 536 (1140) / p99 960 (1547) |
| Concurrent streaming | 1 ms, 20000 rps | 1 ms (1), 20000 (20000) rps |
| Early drop + recovery | 2 ms, recovers | 4 ms (3), recovers |
| Cold construction | 5679 ms / 50 | 87 ms (94) / 50 |

Adjudication: the >5% small-request throughput deltas sit inside run-to-run
noise on this host (after H1 swung 6451 → 7142 rps between runs on the same
tree; 1 MiB swung 2500 → 1818). Absolute times are single-digit milliseconds
for hundreds of loopback requests. Streaming payloads favor eggfetch; cold
construction strongly favors eggfetch (non-hot-path). No material unexplained
regression remains; no TLS/WAF/backpressure/timeout/compat invariant was
weakened for a benchmark win. macOS loopback is not the Linux production
target; numbers are comparative evidence, not latency claims.

## 7. Verification on the proof-bearing tree (`c3568ef4`)

- `cargo fmt --all -- --check`: green.
- Focused nextest
  (`synvoid-http-client`, `-proxy`, `-http`, `-http3`, `-upstream`): 418
  passed.
- `cargo xtask test guards`: 3/3 (repo-guards, root-guards `--features mesh`,
  core-admin-tests).
- Feature profiles: `--no-default-features` with `[]`, `post-quantum`,
  `mesh`, `dns`, `mesh,dns`: all compile.
- `cargo deny check`: green (advisories/bans/licenses/sources ok).
- `cargo audit`: green (6 allow-listed warnings only).
- `cargo xtask verify`: 10/10 green.
- `cargo xtask verify-full`: 10/10 green (profiles, minimal tests, full
  workspace nextest excluding fuzz, doctests).
- `cargo xtask verify-release`: 14/14 green (never publishes; clean tree;
  jail binaries present).
- Per-package `cargo clippy -p synvoid-proxy --all-targets -D warnings` shows
  8 pre-existing `streaming.rs` test-code lints that also fail on unmodified
  `main`; workspace `cargo clippy --all-targets -D warnings` (the CI gate) is
  green. No new routine CI job was added for the benchmark.

Environmental omissions: none blocking. Nightly fuzz smokes and DNS
conformance were not re-run (no DNS-path changes beyond the shared lane;
same scope as Phase 61). `fault_injection_test` (`#[ignore]`, needs built
binary + ~20s) remains out of routine verification per repo policy.

## 8. Production/compatibility lane separation (post-corrective)

- Production uses the eggfetch lane
  (`crates/synvoid-http-client/src/eggfetch_transport.rs` +
  `UpstreamClientRegistry::get_or_create_lane`).
- Legacy Hyper surface stays frozen compatibility-only with unchanged
  aliases/signatures; `eggfetch_lane_freeze_guard` enforces production
  separation (negative-controlled).
- `synvoid-http-client` remains internal (no publication change).

## 9. Decision

**Adopted/closed.** Eggfetch remains the sole production generic egress
transport; the outer registry correctly separates site/policy lifecycles;
invalid requested TLS policy fails before I/O; legacy transport remains
frozen compatibility-only; missing Phase 61 evidence is completed; Phases
58–62 are coherent closed history. Rollback is not triggered.

## 10. Phase 63 closure pointer (2026-09-22)

Final performance/reproducibility authority has moved to
`architecture/eggfetch_0_2_transport_performance_requalification.md`
(Phase 63, closed). This document stays authoritative for the runtime
policy/TLS correction (§2–§5, §8); its §6/§9 benchmark conclusion is
historical short-run evidence only and must not be cited as parity proof.
Phase 63 outcome: parity adjudicated across 10 immutable session datasets
with one accepted, labeled tail residual (`stream-concurrent` under
synchronized concurrency ≥ 4); no production runtime change was required.
