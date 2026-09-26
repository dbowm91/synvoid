# EggServe 0.3 H1 Adoption Closeout (Phases 73–80)

Final disposition at Phase 80: **ADOPTED**. The Phase 78 terminal claim is
superseded by the corrective record below. Post-adoption review found four
concrete defects; Phase 79 corrected them and Phase 80 requalified the
production baseline. No rollback was taken.

Plaintext and TLS-ALPN H1 production run the pinned EggServe direct
runtime; Hyper remains for H2, egress, and test-only differential lanes.
No rollback triggers fired at any point.

## Final ownership

```text
SynVoid (unchanged ownership)
  bind / accept / flood / protocol sniff / TLS termination / SNI / PQ /
  JA4 / ALPN / H2 + H3 transports / admission / WAF / routing / backends /
  per-site response metadata / worker drain
        | caller-owned H1 stream (plaintext TCP / completed Rustls)
        v
EggServe direct H1 0.3.1 (parser/framing, body/tunnel mechanics,
driver + graceful close, response framing)
        v
SynVoidEggserveService (src/http/eggserve_h1.rs: neutral request/body/
upgrade adapter, single policy projector)
        v
existing synvoid-http policy/backend pipeline (shared with Hyper lane)
```

No EggServe listener, TLS termination, H2/H3, static-serving, or CLI
ownership entered SynVoid.

## Exact versions/checksums

| Crate | Version | SHA-256 | Status |
| --- | --- | --- | --- |
| `eggserve-server` | `0.4.0` | `fb601019a2914ae99f264640b66c80496a67b7ea3315fd0809747d4f22327e40` | **current production pin** (Phase 79 Finding B) |
| `eggserve-primitives` | `0.2.2` | `78fd797e45a374bfa419bc75f7e497653ce25e24cde0e771cc332e267f18355c` | **current production pin** (Phase 79 Finding B) |
| `eggserve-server` | `0.3.1` | `987b5873f0273b4d02f81f8e19613c93825803c224e972c86e9e9888098f3de8` | adoption-era pin (Phases 73–79) |
| `eggserve-primitives` | `0.2.1` | `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101` | adoption-era pin (Phases 73–79) |

Pinned `=` in root `Cargo.toml` (production) and `synvoid-http`
dev-dependencies (tests). No `eggserve-core`. `http-interop` on
primitives is a dependency-free cfg gate for trailer accessors. The
0.3.1 → 0.4.0 move is justified and recorded in
`architecture/eggserve_0_4_0_trailer_head_addendum.md`.

## Qualification SHAs

- Pre-adoption baseline: `b14dc7fc` (plans: close EggServe 0.3 gate as
  retained); all campaign work applied above it in the working tree.
- Rollback point: reverting the working tree to `b14dc7fc` restores the
  qualified Hyper production path (no migrations ran before Phase 76).
- Toolchain `1.98.1`, profiles `ci` (routine) / `release` (perf +
  footprint), host `darwin x86_64` for the numbers below (same-host
  only, never across hosts).

## Config matrix result (Track C)

Full valid SynVoid range preserved end-to-end, proven live on both
lanes: parser buffer through 5 MiB, header counts through 10,001,
aggregate ingress through 1.5 MiB under External ownership, low
ceilings (100 B), streaming body bounds, deprecated compat keys parsed,
admission queueing. `RETAIN_PENDING_UPSTREAM` blockers from 0.3.0 are
closed by the 0.3.1 contract (addendum).

## Adversarial result (Track B)

Slow request lines/headers (408/timeout), invalid Host (approved
difference: EggServe pre-service authority validation 400s vs Hyper
routing 404 — both deny 4xx), obs-text relay parity, 12 MiB body
refusal, early-EOF resilience, 3× pipelining, upgrade variants
(no-Connection stays ordinary; missing key still 101s), garbage-start
refusal, conflicting framing refusal, duplicate-`Date` single-value
invariant (canonical correction found by the differential), WAF
stealth-Drop 404 + token, WS handshake parity, keep-alive sequences —
green on both lanes except the two explicitly approved divergences
(header order normalization; invalid-authority 400-vs-404).

## WebSocket result (Track E)

Handshake (101/accept/subprotocol), read-ahead echo, 60 KiB tunneled
messages, half-close resilience, 3× concurrent tunnels, tunneled echo
through a live upstream on both lanes. The Phase 78 record's
app-server gap is **closed by Phase 79**: `GranianSupervisor` with a
test-owned `socket_path`, never started, installed under the test site,
looping a real Unix-socket AppServer peer through production
`maybe_handle_websocket_upgrade` — proven on plaintext and TLS-H1 in
`plaintext_appserver_tunnel_loopback` /
`tls_h1_appserver_tunnel_loopback` (handshake, read-ahead exactly-once,
bidirectional payload, peer close and worker shutdown with no owned-task
leak), with no Python or Granian in CI.

## Performance result (Track G, manual-only)

Same host/process, interleaved, `tests/eggserve_h1_perf.rs` (`--ignored`,
never CI). Release profile:

| Workload | Hyper | EggServe | Delta |
| --- | --- | --- | --- |
| sequential GET p50/p95 | 64 / 161 µs | 70 / 174 µs | +9% / +8% |
| concurrent 16×50 throughput | 13,129 req/s | 16,347 req/s | +24% |
| 1 MiB POST p50 / mean | 1,178 / 1,234 µs | 1,372 / 1,547 µs | +16% / +25% |

RSS coarse 23→24 MiB (whole test binary, both lanes + fixtures).
Dev-profile gaps were larger (~14%); release narrows the common path to
single-digit microseconds while concurrent favors EggServe. The
streaming-body overhead (extra bridge layers) is accepted as a
documented tradeoff; no material common-path regression, no rollback.

## Dependency/footprint delta (Track H)

- `cargo tree`: EggServe leaves are all pre-existing graph members
  (`hyper`, `hyper-util`, `http`, `http-body`, `bytes`, `tokio`,
  `futures-util`, `httpdate`); no core/static/PHF.
- Hyper remains: H2 server/client, egress, test lanes. Truthfully NOT
  removed.
- Release binary: baseline `b14dc7fc` build 78,390,544 B vs adopted
  78,870,400 B (**+479,856 B, +0.6%**), same profile/host.
- Root ledger (`architecture/root_dependency_ownership.md`) reclassified
  `http-body` and added the two EggServe rows (composition_runtime,
  `http, tls`).

## Retained residuals

1. Test-only Hyper differential lanes kept (differential + adoption +
   perf files) against the Phase 78 removal note: they encode the
   acceptance evidence and cost zero production surface; removal would
   destroy re-verification.
2. `src/http/h1_policy.rs` kept for those lanes and its unit tests.
3. Duplicate-`Set-Cookie` collapse via `insert` (pre-existing, identical
   both lanes) deferred to a separate plan.
4. Declared-length oversize maps to 403 (chunk-path `BlockedByWaf`)
   while unknown-length maps to 413 (pre-existing, identical both
   lanes); relabeling deferred.
5. Production H2 `max_header_list_size(max_headers)` byte-unit
   tightness at default (pre-existing, explicitly untouched per
   Phase 77 Track C); needs a separate compatibility plan.
6. ~~App-server tunneled traffic loopback~~ — **closed by Phase 79**
   (see WebSocket result); no residual remains.
7. ~~Hosted CI green for the final SHA~~ — the Phase 78 claim rested only
   on local `cargo xtask verify` 10/10 and is **withdrawn**; hosted proof
   is re-established by Phase 80 Track D (run identity recorded in the
   corrective record below).

## Corrective record (Phases 79–80)

Plan: `plans/phase_79_eggserve_0_3_1_h1_runtime_correctness_corrective.md`
(Finding A–D implementation) and
`plans/phase_80_eggserve_0_3_1_corrective_requalification_and_evidence_closure.md`
(requalification + closure).

- Adoption baseline: `2242e1911d2083448371f707392fdb07f83f1bce`.
- Phase 79 implementation SHA: `171dd1e47f965b04b34465fc72c87adf4d9a9cab`.
- Phase 80 proof-bearing SHA: `174fdbcd6f133b35099ed4492f5ed8d3fcaa7d4c`
  (contains the Phase 79 runtime corrections and the parser-parity guard
  correction; later Phase 80 documentation changes did not change executable
  code).
- Hosted CI: GitHub Actions run `36201213413`, URL
  `https://github.com/dbowm91/synvoid/actions/runs/36201213413`; observed
  2026-09-26. `ci` job `108288055139` and `dependency-security` job
  `108288055300` both completed successfully on the proof-bearing SHA.

### Findings and corrections

| Finding | Correction | Direct proof |
| --- | --- | --- |
| A — worker shutdown dropped the EggServe driver future | shared `drive_h1_connection` signal-then-drain in `src/http/server/accept_loop.rs` and `src/tls/server.rs` | `plaintext`/`tls_h1` `idle_shutdown_drains_connection_task`, `inflight_stream_drains_without_truncation`, `websocket_shutdown_terminates_tunnel`; unit `old_select_drop_pattern_cancels_driver_on_shutdown` pins the pre-corrective failure |
| B — exact buffered responses dropped terminal trailers | `convert_response` keeps the collected trailer block and supplies the head-time `TrailerDeclaration`; pins moved to EggServe 0.4.0 / primitives 0.2.2 | `exact_small_body_with_trailers_keeps_length_and_trailers`, `exact_zero_data_with_trailers_uses_known_zero_stream`, `exact_body_without_trailers_keeps_bytes_fast_path`, `unknown_length_trailers_stay_on_streaming_path`, `plaintext_exact_trailer_wire_block`, `tls_h1_exact_trailer_wire_block` |
| C — Phase 78 never looped the AppServer tunnel | `UnixStream::connect` + `client_async` AppServer dial; test-owned `GranianSupervisor.socket_path` | `plaintext_appserver_tunnel_loopback`, `tls_h1_appserver_tunnel_loopback` |
| D — local endpoint fabricated from the peer address | `h1_connection_context` never substitutes the remote peer; missing local fails the context | `connection_context_never_substitutes_peer_for_local`, `connection_context_preserves_truthful_local`, `connection_context_tls_selects_https_scheme`, `request_conversion_resolves_peer_without_local` |

New suite: `tests/eggserve_h1_runtime_corrective.rs` (10 tests,
`tests/OWNERSHIP.toml` entry). The in-flight drain tests use a
streaming-policy site whose WAF tarpit is served as a live
SynVoid-generated stream, because the default buffered proxy policy
collects an upstream body before any byte reaches the client and cannot
be in flight when shutdown lands.

### Focused regression requalification (Phase 80 Track A)

92/92 across `eggserve_h1_runtime_corrective`, `eggserve_plaintext_adoption`,
`eggserve_tls_h1_convergence`, `eggserve_h1_differential`,
`http_h1_tls_transport`, `http_h1_parser_parity`, `http_tls_parity`,
`http_transport_neutrality_guard`, `http_normalization_ownership_guard`,
`http_differential_closure`, plus 22/22 focused `http::eggserve_h1` unit
tests. Re-run 2026-09-26 with `cargo nextest run --cargo-profile ci
--profile ci --test eggserve_h1_runtime_corrective --test
eggserve_plaintext_adoption --test eggserve_tls_h1_convergence --test
eggserve_h1_differential --test http_h1_tls_transport --test
http_h1_parser_parity --test http_tls_parity --test
http_transport_neutrality_guard --test http_normalization_ownership_guard
--test http_differential_closure` (92/92) and
`cargo test --profile ci eggserve_h1:: --lib` (22/22). Contract coverage
recorded: per-site Date/Server
(`differential_site_metadata`, `metadata_no_token_site`,
`tls_h1_control_and_metadata`), parser/aggregate caps above the former
0.3.0 limits (`config_big_buffer_range`, `config_big_ingress_range`,
`config_many_headers_range`, `parser_maxima_parity`,
`differential_aggregate_header_431`, `tls_h1_parser_bounds_and_timeout`),
WAF Drop ordering (`differential_waf_drop`, `tls_h1_body_limits_and_drop`),
keep-alive/pipelining (`differential_keepalive_sequence`,
`adversarial_pipelined_sequence`, `slow_reader_gets_full_stream`), H2 ALPN
guard (`tls_h1_real_alpn_negotiates_http11_and_serves_control`,
`plaintext_has_no_h2`, `tls_h2_branch_stays_hyper`,
`tls_h2_stays_hyper_with_header_limit`).

One stale guard was found and adjudicated during Track A:
`http_h1_parser_parity::tls_h1_uses_shared_policy_and_keeps_upgrades_and_h2`
still asserted the pre-adoption Hyper wiring, which `2242e191` replaced.
That binary is not part of `cargo xtask verify`, so it had been red since
the adoption while `architecture/http_h1_runtime_truthfulness_phase70.md`
still reported 10/10. The guard now pins the current wiring truth
(shared `project_eggserve_h1`, shared `h1_connection_context` /
`drive_h1_connection` / `EggserveH1Service`, unchanged H2
`max_header_list_size`) and passes 10/10 again. This is an evidence-truth
fix, not a runtime change.

### Performance/resource recheck (Phase 80 Track B, manual-only, never CI)

Same host and release harness as Phase 78. Three consecutive runs of
`cargo test --release --test eggserve_h1_perf -- --ignored --nocapture`
on 2026-09-26 produced these same-run ranges:

| Workload | Hyper range | EggServe range | Same-run reading |
| --- | --- | --- | --- |
| sequential keep-alive GET p50 / p95 | 108–133 / 205–398 µs | 108–138 / 205–419 µs | p50 within 5%; p95 tracks within noise |
| concurrent 16×50 throughput | 12,484–14,683 req/s | 11,790–14,896 req/s | run-to-run reversal; no stable loss |
| 1 MiB streamed POST p50 / p95 | 589–1,238 / 880–2,983 µs | 597–1,287 / 865–3,156 µs | p50 within 5%; tail tracks within noise |

Per-run concurrency ratios (EggServe / Hyper) were 0.89, 1.15, and 1.01;
the sequential p50 ratios were 1.04, 1.00, and 1.04. The harness is short
and visibly noisy, with occasional millisecond outliers, so the accepted
Phase 78 raw comparison remains the authority for the campaign-level
performance disposition. These three runs show no repeatable regression
introduced by the corrective. Coarse RSS of the whole perf test binary
started at 35–38 MiB and ended at 40 MiB (both lanes + fixtures;
allocator-dependent, not a process footprint claim).

Trailer-bearing exact responses are covered functionally by the wire
tests above rather than benchmarked (no Phase 78 historical equivalent);
the no-trailer exact path is the sequential/concurrent workload above.

## Verification

At Phase 80, `cargo fmt --all -- --check`, `cargo xtask test guards`,
`cargo nextest run -p synvoid-http --cargo-profile ci --profile ci`
(139 passed), `cargo nextest run -p synvoid-config --cargo-profile ci
--profile ci` (93 passed), the five no-default-feature profile checks
(minimal, post-quantum, mesh, dns, mesh,dns), `cargo deny check`,
`cargo audit`, and `cargo xtask verify` all passed. `cargo xtask verify`
passed 10/10 steps, including fmt, clippy `-D warnings`, dependency
policy, core compile, repo guards, security regression, root guards, core
admin tests, admin contract, and failure injection. Suite deltas added by
the campaign:
`eggserve_0_3_1_qualification` (28), `inbound_neutral_boundary` (13),
`eggserve_h1_differential` (23), `eggserve_plaintext_adoption` (11),
`eggserve_tls_h1_convergence` (5), `eggserve_h1_perf` (3, ignored);
guards extended (`http_transport_neutrality_guard` 7/7, boundary
exceptions maintained live).

Broader optional handoff `cargo xtask verify-full` was attempted on
2026-09-26: 8/9 steps passed (fmt, clippy, minimal/mesh/dns/icmp/mesh+dns
profiles, and minimal tests). Its workspace nextest compile failed while
writing `synvoid-mesh` / `synvoid-dns` artifacts with `No space left on
device`; the full workspace suite and subsequent doctests did not run. A
direct retry of the nextest step was stopped while blocked behind concurrent
Cargo work on the shared host. The required Phase 80 `cargo xtask verify`
and direct HTTP/config/guard matrices passed independently.

### Phase 80 terminal disposition

**ADOPTED**, based on the corrected EggServe H1 implementation at Phase 79
SHA `171dd1e47f965b04b34465fc72c87adf4d9a9cab`, direct Phase 80 local
requalification, and hosted CI run `36201213413` on proof-bearing SHA
`174fdbcd6f133b35099ed4492f5ed8d3fcaa7d4c`. Phase 78's terminal claim is
superseded; its valid historical correctness/performance evidence remains
preserved above. No registered downstream plan depended on Phase 80. The
H2 header-list byte-unit review, duplicate `Set-Cookie` behavior,
body-limit status relabeling, and test-only Hyper differential-lane decision
remain separate follow-up candidates.
