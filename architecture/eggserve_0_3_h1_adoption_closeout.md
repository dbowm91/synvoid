# EggServe 0.3 H1 Adoption Closeout (Phases 73–78)

Disposition: **ADOPTED**. Plaintext and TLS-ALPN H1 production run the
pinned EggServe direct runtime; Hyper remains for H2, egress, and
test-only differential lanes. No rollback triggers fired.

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

| Crate | Version | SHA-256 |
| --- | --- | --- |
| `eggserve-server` | `0.3.1` | `987b5873f0273b4d02f81f8e19613c93825803c224e972c86e9e9888098f3de8` |
| `eggserve-primitives` | `0.2.1` | `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101` |

Pinned `=` in root `Cargo.toml` (production) and `synvoid-http`
dev-dependencies (tests). No `eggserve-core`. `http-interop` on
primitives is a dependency-free cfg gate for trailer accessors.

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
through a live upstream on both lanes. App-server tunneled traffic was
not looped (no supervisor fixture); the path shares the proven neutral
dispatch and remains a 78-follow-up integration item with the real
app-server suite.

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
6. App-server tunneled traffic loopback (see WebSocket result).
7. Hosted CI green for the final SHA (local `cargo xtask verify` 10/10
   repeatedly through every phase).

## Verification

`cargo xtask verify` 10/10 at every phase gate (73 re-run, 74, 75, 76,
77, and this closeout), including fmt, clippy `-D warnings`, deny/audit,
all feature profiles, guards, security regression, admin contract, and
failure injection. Suite deltas added by the campaign:
`eggserve_0_3_1_qualification` (28), `inbound_neutral_boundary` (13),
`eggserve_h1_differential` (23), `eggserve_plaintext_adoption` (11),
`eggserve_tls_h1_convergence` (5), `eggserve_h1_perf` (3, ignored);
guards extended (`http_transport_neutrality_guard` 7/7, boundary
exceptions maintained live).
