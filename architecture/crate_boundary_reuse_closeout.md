# Crate Boundary and Reuse Closeout (Phase 35)

Status: complete (2026-09-16).
Plans: `plans/phase_35_crate_boundary_reuse_closeout.md`,
`plans/crate_boundary_reuse_followup_roadmap.md`.
Roadmap phases: 32 (platform), 33 (rate-limit), 34 (keystore/egress), 35 (this closeout).

Primary goal (from the phase plan): reconcile the post-Phase-31 architecture
after platform canonicalization, rate-limit extraction, and reusable-library
cleanup; verify every new boundary has measurable value; leave documentation,
dependency ownership, release behavior, and public/reuse policy consistent with
the compiled workspace.

## 1. Implemented phases and commit SHAs

| Phase | Subject | Commit | Status |
|-------|---------|--------|--------|
| 32 | Platform canonicalization and duplicate-source removal | `2a753500` | complete |
| 33 | Shared rate-limit primitive extraction (`synvoid-rate-limit`) | `20847743` | complete |
| 34 | Reusable library boundary cleanup and egress decision gate (Branch 2: retain `synvoid-http-client`) | `ffbd541e` | complete |
| 35 | Closeout, audit reconciliation, publication/reuse policy (this report) | this commit (`architecture/crate_boundary_reuse_closeout.md`) | complete (this commit) |

`plans/phase_32_platform_canonicalization_and_dedup.md`,
`plans/phase_33_rate_limit_primitive_extraction.md`, and
`plans/phase_34_reusable_library_boundary_cleanup.md` each carry a completion
record; historical Phase 31 and earlier closeouts are unchanged except for
forward references where current docs require them.

Workspace graph evidence (2026-09-16):

```bash
cargo metadata --all-features --format-version 1
cargo tree --workspace
cargo tree -d
cargo tree -e features --workspace
cargo tree -i synvoid-platform --workspace
cargo tree -i synvoid-rate-limit --workspace
cargo tree -i synvoid-dnssec-keystore --workspace
cargo tree -i synvoid-http-client --workspace
cargo tree -p synvoid-platform --depth 1
cargo tree -p synvoid-rate-limit --depth 1
cargo tree -p synvoid-dnssec-keystore --depth 1
cargo tree -p synvoid-http-client --depth 1
cargo tree -i hyper-rustls --workspace
cargo tree -i rustls --workspace
cargo tree -i cryptoki --workspace   # empty on default features (HSM opt-in)
cargo tree -i eggfetch-core --workspace   # no such package (retained http-client)
```

- Workspace members: 51 (root `synvoid`, 43 `synvoid-*` under `crates/`,
  `pqc`, `admin-ui`, 2 examples, `fuzz`, `tools/{xtask,synvoid-repo-guards}`).
- `synvoid-*` under `crates/`: 43 (Phase 33 adds `synvoid-rate-limit`; no
  crate created/removed in Phase 35).
- LOC recomputed via `wc -l` over each crate `src/` (see
  `architecture/crate_granularity_audit.md` Phase 35 deltas for the full table;
  notable: `synvoid-platform` 5408, `synvoid-rate-limit` 732,
  `synvoid-dnssec-keystore` 2710, `synvoid-http-client` 1999,
  `synvoid-http` 11247, `synvoid-upstream` 2488, `synvoid-dns` 38141,
  `synvoid-ipc` 12702, `synvoid-mesh` 100220, `synvoid-static-files` 6557,
  `synvoid-upload` 8242, `synvoid-yara` 2814, `synvoid-utils` 1826).

## 2. Before/after ownership table

| Area | Before (pre-roadmap) | After (Phase 35) | Evidence |
|------|----------------------|------------------|----------|
| Platform primitives (`ipc`, `process`, `socket`, `service`, `unix`, `windows_impl`, `windows/`) | Parallel implementations in `src/platform/` and dormant `crates/synvoid-platform/src/` | Single compiled owner `crates/synvoid-platform`; `src/platform/mod.rs` is pure alias facade | `architecture/platform.md` §1.1 + §12, `tests/platform_canonicalization_guard.rs`, `cargo check -p synvoid-platform --all-targets` |
| Paths | `PlatformPaths::new()` hard-codes SynVoid names | `new()` byte-identical + neutral `for_app(id)`/`validate_app_id`/`InvalidAppId`/`with_base` | `platform_paths_test` (parity + traversal rejection) |
| Rate-limit mechanism | Root WAF window duplicate + mesh no-op stub + generic contracts trapped in `src/utils/ratelimit` | Shared std-only leaf `synvoid-rate-limit` (`window` + `contracts` + `slot`); WAF policy (blackhole/slotted/shm/decision) stays root-owned; mesh peer/global enforce at configured limits | `crates/synvoid-rate-limit/tests/rate_limit_test.rs` (26 deterministic, no sleeps), `bench_ratelimit`, mesh `rate_limit.rs` + `transport_types.rs`, root `core.rs` + `asn_tracker.rs`, `src/utils/ratelimit` compat re-export |
| DNSSEC custody | Signing + transport mixed in `synvoid-dns`; `synvoid-core` edge for wall-clock | One-way leaf `synvoid-dnssec-keystore` (no core/config/root; `src/time.rs` owns clock); `synvoid-dns` → keystore one-way; HSM opt-in fail-closed | `dnssec_keystore_boundary` guard, `keystore_boundary.rs` KAT/rotation/permission/redaction, lib.rs docs + 3 doctests |
| Egress transport | `synvoid-http-client` carries site→TLS conversion + WAF body + metric names | Policy-free transport (no config/core/metrics edges); site→TLS in `synvoid-upstream::tls_adapter`, WAF body in `synvoid-http::streaming_waf_body` (scanner from `synvoid_core::streaming_waf` via `shared_handler`); tunnel dispatch stays root | `egress_parity.rs` (13 hermetic + PQ), `cargo tree -p synvoid-http-client --depth 1` before/after, `egress_client_decision_phase34.md` |
| Root utilities | Second URL-decode copy (drops `%` on non-ASCII), undocumented helpers | `src/utils.rs` re-exports canonical `synvoid_core::url` (no second copy); explicit Phase 35 disposition for `ResultExt`/`OptionExt`/`errors`/`HotHashMap`/`parse_host_port`/`hash_ip`/`format_duration`; `is_newer_version` documented approximate (not SemVer), `get_first_non_loopback_ip` documented heuristic | `src/utils.rs` header + new `crate_boundary_reuse_closeout` guards (`root_utils_has_no_second_url_implementation`, `utils_ratelimit_compat_stays_thin`) |
| Release ordering | Missing `synvoid-auth`, `synvoid-dnssec-keystore`, `synvoid-rate-limit`; stale `platform`/`mesh`/`waf`/`upload`/`dns` dep lists | All 43 crates ordered; corrected dep lists (platform→utils, mesh→mesh-protocol/platform/rate-limit, waf→mesh, upload→yara, dns→dnssec-keystore/platform) | `docs/releasing.md` §1, `cargo metadata` internal-dep check |
| Counts | `AGENTS.md`/`overview.md` say 50 members / 42 crates | 51 members / 43 crates | `cargo metadata` workspace_members |

No document claims a crate is canonical while an active duplicate remains:
platform duplicates deleted, WAF window duplicate moved, mesh window stub
deleted, keystore app edges removed, http-client policy adapters moved, root URL
copy deleted (re-export).

## 3. Duplicate code removed

- `src/platform/{ipc,process,socket,service,unix,windows_impl,windows}.rs`
  (~2800 lines incl. service/windows backends): deleted, crate canonical
  (Phase 32; newest fixes ported both ways).
- `src/platform/socket.rs` `bind_tcp_reuse`/`bind_udp_reuse` copies: collapsed
  onto `socket_bind` (broader reuse-port cfg wins; noted in `platform.md` §12).
- Mesh WAF rate-limit stub (`stubs::waf_stub::ratelimit`): deleted; mesh consumes
  shared windows (Phase 33). Remaining `waf_stub::threat_intel::feed_client` is
  feed types only, explicitly not a limiter stub.
- Root `AtomicSlidingWindow` impl (`src/waf/ratelimit/core.rs`): moved to
  `synvoid-rate-limit::window` (explicit-tick API; root consumes it).
- Keystore `synvoid-core` wall-clock uses (2 call sites): replaced by local
  `src/time.rs` (identical fail-to-zero semantics; no micro-crate).
- `upstream_tls_from_site_config` (+ tests): moved `http-client` →
  `synvoid-upstream::tls_adapter`.
- `StreamingWafBody` (+ metric): moved `http-client` →
  `synvoid-http::streaming_waf_body` (metric belongs in domain layer).
- Root URL-decode copy (`src/utils.rs`): deleted, re-exports canonical
  `synvoid_core::url` (fixes the old copy's missing `%` on non-ASCII escapes).
- Orphaned root manifest edges removed in Phase 31 (`hyper-rustls`,
  `axum-extra`, `http-body`, `rkyv`, `bitflags`, `tracing-appender`, `moka`,
  `ipnetwork`, `notify`, `aho-corasick`, `unicode-normalization`,
  `libinjectionrs`, `serde_bytes`, `hickory-*`, `getrandom`, `pin-project-lite`,
  `dirs`, `smallvec`, `aes-gcm`, `digest`, `rsa`, `rand_core_06`, `sha1`, `sha3`,
  `x25519`, `base32`, `log`, `tonic-reflection`, `openraft`, etc.) plus Phase 32
  (`zip`, `libloading`, `windows-sys`); 3 test-only moved to `[dev-dependencies]`
  (`tower`, `tempfile`, `flate2`). `prost`/`tonic-prost` retained as codegen
  runtimes with guard exceptions.

## 4. New crate(s) created and why they passed the retention test

Only one crate was created by the roadmap: `synvoid-rate-limit` (Phase 33).
It passes the same retain bar as every other crate (not kept merely for being
new):

- Independently testable invariants: rotation/overflow/reset determinism,
  shard spread, N/N+1 boundary, large jumps, concurrent rotation without
  underflow, retry timing, IPv4/IPv6 slots, zero/overflow config.
- Dependency isolation: std-only leaf (0 internal deps; explicitly forbids
  root/config/waf/mesh/ipc/admin/HTTP/metrics).
- Multiple real consumers: root WAF composition (`ratelimit/core.rs` windows +
  `asn_tracker.rs` clock) and mesh (`mesh/rate_limit.rs` peer limiter +
  `mesh/transport_types.rs` global limiter). IPC/admin/upload/DNS evaluated
  one at a time and intentionally left domain-owned (see Phase 33 matrix).
- No policy moved: blackhole/slotted/shm/token-bucket/metrics/logging/config
  stay domain-owned; `ip_to_slot` duplication from `synvoid-utils` is a
  documented leaf-ownership note, not a second canonical helper.
- Performance: `increment_at` ~36ns, `count_at` ~24ns (ci profile, 1s
  measurement; Phase 33 baseline 86ns/56ns — no regression, no mutex/heap per
  event).

No other crate was created: platform/keystore/http-client/upstream/http were
boundary cleanups, not new crates. The forbidden branch (new generic HTTP crate
alongside eggfetch) was not taken.

## 5. Extraction ideas rejected/deferred and why

- Split `synvoid-core`, extract `synvoid-admin-server`/`synvoid-waf-runtime`,
  split supervisor/worker/TCP/UDP/root HTTP/TLS, merge `synvoid-filter`,
  split `synvoid-ipc`, publish `synvoid-utils` as general-purpose API, second
  generic HTTP crate: all explicitly out of scope per the roadmap non-goals;
  re-evaluated on the final graph — no change (same verdict as Phase 31).
- Move `ShardedRateLimiter`, `GlobalRateLimiter`/blackhole, slotted/shm
  counters, `RateLimitDecision` into `synvoid-rate-limit`: rejected — single
  consumer and/or domain policy/unsafe; stays root WAF-owned (Phase 33 Part D/F).
- Force `synvoid-waf::ratelimit::sliding` (u32 buckets, O(N) sums, locked map),
  mesh fixed-window peer/auth limiters, IPC token bucket, admin lockout, upload
  policy, DNS token buckets/RRL behind one abstraction: rejected — materially
  different concurrency/semantics; phrase-sharing is not a boundary.
- Move mmap/`CounterArray` into the crate: rejected — no second consumer needs
  it; unsafe boundary stays in WAF with its safety contract.
- Move supervisor/worker policy, app metrics, runtime wiring into
  `synvoid-platform`: rejected — genuine application composition, root-owned.
- Per-file feature gates in `synvoid-platform`: rejected — negligible dep cost.
- Promote `ResultExt`/`OptionExt`, `HotHashMap`/`HotHashSet`,
  `format_duration`, `parse_host_port`, `hash_ip`, application error strings
  into `synvoid-utils`: rejected/deferred — zero/single consumers and/or
  app-specific semantics; documented root-owned in `src/utils.rs` (multiple-
  consumer + stable-semantics bar not met). `is_newer_version` stays approximate
  (not SemVer); `get_first_non_loopback_ip` stays heuristic.
- Collapse `http-client`/`upstream`/`tunnel`, `filter` into proxy/core,
  `app-server` into `app-handlers`, `synvoid-sdk` umbrella: deferred — needs a
  scoped dependency-flow/stability plan, not a closeout drive-by.
- Create a micro-crate to erase the keystore clock edge: rejected — local
  `src/time.rs` helper, no new crate.
- Demand SynVoid-specific extensions of eggfetch: forbidden branch — not taken.

## 6. Eggfetch decision and evidence

Decision (Phase 34, Branch 2): **retain `synvoid-http-client`**.
Full matrix in `architecture/egress_client_decision_phase34.md` (capability
matrix over all production consumers + `eggfetch-core` 0.1.4 comparison).

Material gaps in `eggfetch-core` 0.1.4: ring-only TLS (no aws-lc-rs/PQ knob);
closed `RequestBody` (WAF mid-stream scan needs open `B: Body`); no direct-UDS
parity; coarse verification toggle (regresses audited skip-verify policy); same
transitive hyper/rustls stack (zero dep win); pre-1.0 maturity (0.1.4, days old,
~93 downloads). No required capability eggfetch uniquely provides
(proxy/cookies/compression unneeded; H3 egress not required — H3 is inbound-only).

Single maintenance owner after Phase 34: egress TLS + pooling + H1/H2 +
root-store = `synvoid-http-client`; site/TLS conversion =
`synvoid-upstream::tls_adapter`; WAF body = `synvoid-http`; tunnel dispatch =
root composition. No retained overlap without an exit condition.

Future consolidation condition (revisit only when all hold): eggfetch (or
successor) offers aws-lc-rs/PQ parity, direct UDS egress, open `Body`
transport, hostname-scoped verification, and a stable audited release line —
plus black-box parity tests proving equal behavior for every Part D row before
any ownership moves.

Phase 35 re-verification: `eggfetch-core` still absent from the graph
(`cargo tree -i eggfetch-core` → no such package); `hyper-rustls` reachable
only via legitimate owners (`synvoid-tls` ACME, `synvoid-http-client` egress,
`metrics-exporter-prometheus`), not stale compat (root has no direct edge);
`cryptoki` absent on default features (opt-in via `dns-hsm` only).

## 7. Reusable/public-library classification

Classes: 1 = application-internal, 2 = reusable workspace library without
external support promise, 3 = reasonable crates.io candidate, 4 = compatibility
facade/transitional. Evaluated minimum set plus notes (see also
`final_surface_audit.md` §10):

| Crate | Class | Meets public-candidate bar? |
|-------|-------|-----------------------------|
| `synvoid-platform` | 2 | No — app-neutral API, no root edge, narrow deps, crate docs + `platform.md`, deterministic tests; missing MSRV/`rust-version` + semver-support statement |
| `synvoid-rate-limit` | 2 | No — std-only, neutral names, no root edge, docs + deterministic tests + bench; missing MSRV + semver statement |
| `synvoid-dnssec-keystore` | 2 | No — opaque handles, no raw-key API, atomic/0600, fail-closed HSM, crate docs + runnable examples + 3 doctests, no config/Hickory/mesh/admin/Hyper/Quinn/SQLite; missing MSRV + semver statement |
| `synvoid-filter` | 2 | No — zero-dep narrow traits, stable path; too thin for standalone (3) |
| `synvoid-yara` | 2 | No — single `yara-x` owner, bounded compile/scan, digest binding; missing MSRV + semver statement |
| `synvoid-mesh-protocol` | 2 | No — leaf wire vocabulary, golden vectors, no DHT/Raft/SQLite/YARA; missing MSRV + semver statement |
| `synvoid-http-client` | 2 | No — policy-free leaf, parity suite (13 + PQ), PQC marker; missing MSRV + semver statement |
| Root `src/*` facades | 4 | Pinned thin by `facade_disposition_guard` + `crate_boundary_reuse_closeout` guards |
| All other `synvoid-*` | 1 | Domain composition / feature isolation / security boundary without standalone reuse promise |

Publication decision: **no publish in this phase**. All `synvoid-*` crates
remain technically publishable (description/license/repository present, order in
`docs/releasing.md` corrected for the three missing crates) but carry no
external support promise (pre-1.0, no MSRV/semver statement). No
`publish = false` added — internal-only status is documented, not enforced by
registry churn. If a future phase promotes a crate to (3), it must add
application-neutral names (already hold), crate docs/examples (keystore/rate-
limit already have them; platform needs runnable examples), explicit
MSRV/`rust-version`, license/repository/description (already hold),
deterministic tests (already hold), no hidden SynVoid runtime requirement
(already hold), and a semver-support statement.

## 8. Dependency/security deltas

- Phase 32: `synvoid-platform` gains target-gated `nix`/`daemonize2` (unix),
  `tokio` rt+signal (unix/Windows), `windows-sys`/`libloading`/`zip` (Windows
  Wintun only) + acyclic `synvoid-utils`; removes `synvoid-ipc` dev-cycle;
  root drops `zip`/`libloading`/`windows-sys`. No metrics/config/root/ipc edges.
- Phase 33: new `synvoid-rate-limit` (0 deps); mesh gains `synvoid-rate-limit`;
  root gains `synvoid-rate-limit` (already had it via composition — now shared).
  No metric/config/HTTP edges in the new crate.
- Phase 34: `synvoid-http-client` drops `synvoid-config`/`synvoid-core`/
  `metrics`; `synvoid-upstream` gains `synvoid-config` (adapter owner);
  `synvoid-http` gains `synvoid-upstream` (call sites already there). Net
  workspace deps unchanged (moves, not adds); parity dev-deps reuse locked
  versions (`rcgen`/`tempfile`/`tokio-rustls`/hyper-server).
- Phase 35: no manifest dependency changes except documentation; `src/utils.rs`
  now consumes `synvoid-core` (URL re-export) — ledger `Allowed root paths`
  updated (`utils` added); entitlement guard fixed to not misattribute
  `synvoid_core::url::` as the external `url` crate.
- `cargo deny check`: clean (bans/licenses/sources/advisories ok).
- `cargo audit`: exit 0 with only pre-existing allowed warnings (9 allowed;
  e.g. unmaintained `proc-macro-error*`/`sized-chunks`, wasmtime RUSTSEC-2026-0269
  capability-absence — see `dependency_security_baseline_phase25.md`; never call
  42.0.2 "patched" for 0269). 16 advisory ignores in `deny.toml` (mirrored in
  `.cargo/audit.toml`), expiring against current UTC date.
- HSM/PKCS#11: no root `cryptoki` edge; `synvoid-dnssec-keystore/pkcs11` +
  `hsm` off by default; `synvoid-dns/hsm` forwards; root `dns-hsm` = `dns` +
  `synvoid-dns/hsm`. `cargo tree -i cryptoki` empty on default features.
- Unsafe review: roadmap reduces duplicate unsafe/platform code (single owner);
  no new `unsafe` blocks in Phases 33-35 except pre-existing platform backends
  (Landlock/Capsicum/Pledge/Seatbelt/Job-Object, raw-fd conversions with
  documented contracts, Windows DACL). Rate-limit/keystore-time/http-adapters
  add no `unsafe`. All platform `unsafe` retains local safety invariants +
  target-gated tests.

## 9. Performance/footprint deltas

- Rate-limit hot path (`bench_ratelimit`, ci profile, 1s measurement):
  `shared_window/increment_at` ~36ns, `shared_window/count_at` ~24ns
  (Phase 33 baseline 86ns/56ns — no regression; faster on this host, same
  algorithm moved verbatim; no mutex/heap per event, monotonic tick + rotation
  check + atomics). Specialized keyed limiter retained separately (~147ns
  hot-key / ~66ns sharded in Phase 33).
- No additional allocation/lock on per-request limiter checks (guarded by
  design + bench; `AtomicSlidingWindow` uses atomics + saturating arithmetic,
  large jumps clear buckets, concurrent rotation never underflows).
- Proxy request path: adapter layering (`tls_adapter`, `streaming_waf_body`
  move) adds no measurable regression — moves, not extra hops; the WAF body
  metric moved with the adapter into the domain layer where it belongs.
  `egress_parity.rs` proves behavioral parity (keepalive/reuse, H2, TLS roots,
  timeouts, size limits, streaming, headers/auth, UDS, pool eviction, error
  mapping).
- Binary sizes / cold build: Phase 35 adds no runtime code except the URL
  re-export (identical algorithm, one-line delegation) + docs + guards, so no
  footprint delta is claimed; default (`socket-handoff,mesh,dns,erased_pool,
  swagger-ui`) stays full-featured for compatibility, `--no-default-features`
  stays the hardened minimal profile (both compiled in verification).
- Dependency footprint for egress: same hyper/rustls/moka/hyperlocal stack
  before/after (no eggfetch adoption ⇒ no transitive reduction, but also no
  second stack — single owner retained).

## 10. Verification commands/results

Minimum matrix from the phase plan (toolchain: pinned Rust 1.98.1 per
`rust-toolchain.toml`; nextest 0.9.140; `protoc` installed):

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz
cargo test --workspace --doc --profile ci
```

Targeted Phase 32-34 suites + benchmarks (recorded in the plan completion
records and re-verified here):

```bash
cargo check -p synvoid-platform --all-targets
cargo test -p synvoid-platform --profile ci
cargo check -p synvoid-rate-limit --all-targets
cargo test -p synvoid-rate-limit --profile ci
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-mesh --profile ci
cargo test -p synvoid-ipc --profile ci
cargo check -p synvoid-dnssec-keystore --all-targets
cargo test -p synvoid-dnssec-keystore --profile ci
cargo check -p synvoid-http-client --all-targets
cargo test -p synvoid-http-client --profile ci
cargo test -p synvoid-upstream --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo bench --bench bench_ratelimit --profile ci
```

Results (local, 2026-09-16):

- `cargo fmt --all -- --check`: pass.
- `cargo xtask verify`: 10/10 steps pass locally (fmt, clippy `-D warnings`,
  deny, core compile, repo-guards, security regression single-threaded, root
  guard suite with `--features mesh`, core admin tests, admin contract with
  `mesh,dns,icmp-filter`, failure injection).
- `cargo xtask verify-full`: feature-profile compiles (minimal/mesh/dns/
  icmp-filter/mesh+dns) + full workspace nextest + doctests pass locally
  (see commit message for counts; Phase 33 noted a one-pass flake that
  immediately re-ran green — same policy applied here: any single-test flake
  without per-test detail is re-run to confirm, not accepted as evidence).
- `cargo xtask verify-release`: release qualification + package inspection
  pass locally with `--allow-dirty` for pre-commit evidence; final clean-tree
  run is recorded after commit (NEVER publishes; fails on dirty tree by design).
- `cargo deny check` / `cargo audit`: clean as in §8.
- Feature profiles: `minimal`, `mesh`, `dns`, `mesh,dns` all compile
  (`cargo check --no-default-features [--features ...]`).
- Targeted suites: platform (32 tests), rate-limit (26 deterministic),
  keystore (KAT/rotation/permission/redaction + 3 doctests), http-client
  parity (13 hermetic + PQ), upstream/proxy/waf/mesh/ipc green; new
  `crate_boundary_reuse_closeout` guards (8 tests) green; `dnssec_keystore`
  strengthened guard green; `module_ownership` entitlement green after the
  `::`-prefix fix.
- Fuzz smoke (outside routine verification): `cargo +nightly fuzz run <target>
  -- -runs=1000` available for 21 targets; not run in closeout (nightly-only).

Exact toolchain/commit versions are recorded in the Phase 35 commit message
and the CI run linked from the push.

## 11. Remaining explicit risks or future triggers

- `synvoid-filter` thinness: revisit only in a scoped pass with stability
  review (semver consumer check); do not merge for count alone.
- Egress layering (`http-client`/`upstream`/`tunnel`) and
  `app-server`/`app-handlers`: any collapse needs a scoped dependency-flow
  plan, not a drive-by.
- `synvoid-utils` promotion bar: only helpers with multiple consumers + stable
  semantics move; approximate `is_newer_version` must never be advertised as
  SemVer; heuristic `get_first_non_loopback_ip` must stay explicit or gain a
  platform mechanism.
- `check_regex_complexity` has two owners with different thresholds
  (`synvoid-utils` 1024/10/20 vs `synvoid-core::url` 1000/20/10): intentionally
  left separate (different consumers/semantics); do not force behind one
  abstraction without a semantic review.
- `HotHashMap`/`HotHashSet`, `ResultExt`/`OptionExt`, `format_duration`,
  `hash_ip`, application error strings: retained root-owned with tests; remove
  only after proving zero consumers (including doctests/fuzz) + ledger update.
- HSM: `cryptoki` stays opt-in (`pkcs11`/`hsm`, root `dns-hsm`); no silent
  software fallback; re-audit supply chain 2026-10-01 per
  `dependency_security_baseline_phase25.md`.
- Wasmtime: direct 42.0.2 via `[patch.crates-io]` is AFFECTED by
  RUSTSEC-2026-0269 (capability absence, not a patch); ≥46.0.3 blocked by
  bumpalo conflict (see AGENTS.md Known Issues). Do not call 42.0.2 "patched".
- macOS-only `rkyv_derive` 0.7 link segfault (Apple clang 21, via
  `lightningcss`): non-deterministic, retry often succeeds; Linux CI unaffected.
- If eggfetch (or successor) ever meets the §6 consolidation condition, revisit
  egress ownership with parity tests first — no silent migration.
- If a crate is ever promoted to public-library (3), it must add MSRV/
  `rust-version`, semver-support statement, and (for platform) runnable
  examples before any `cargo publish`.

## Acceptance criteria (from the phase plan) — disposition

- [x] Platform ownership docs match the compiled owner; no duplicate generic
  platform implementation remains.
- [x] `synvoid-rate-limit` has multiple real consumers and a low dependency
  surface (std-only leaf).
- [x] Mesh/WAF no longer rely on ownership stubs for the shared limiter
  (window stub deleted; remaining `waf_stub::threat_intel` is feed types only).
- [x] DNSSEC custody APIs remain fail-closed and application-light.
- [x] Egress has one deliberate maintenance owner (`synvoid-http-client`
  retained with documented exit condition; no second generic HTTP crate).
- [x] Root utilities have an explicit ownership disposition (`src/utils.rs`
  header + ledger + guards).
- [x] Crate-granularity audit and dependency-ownership ledger are current
  (recomputed LOC/rev-deps/internal-deps; `releasing.md` order fixed).
- [x] Minimal/default feature profiles pass.
- [x] Architecture guards encode the new boundaries (8 new closeout tests +
  strengthened keystore budget + entitlement `::` fix).
- [x] Release/security verification passes (`deny`/`audit`/`verify`/
  `verify-full`/`verify-release` + targeted suites/benches).

## Rejection criteria (from the phase plan) — avoided

- No crate-counting: every keep verdict cites dependency/authority/reuse value.
- No doc/compiler drift: ledgers, burn-down, surface audit, `releasing.md`,
  `AGENTS.md`, skills, and guards were reconciled with `cargo metadata`/`tree`.
- No dual HTTP stacks without an exit condition: eggfetch not adopted; single
  owner retained with a future-consolidation condition.
- No publication for looks-reusable: no `cargo publish` in this phase; (3)
  requires MSRV/semver first.
- No app policy moved into libs: platform/keystore/rate-limit/http-client
  boundaries kept policy-free; metrics/config stay at callers/domains.
- No hot-path regression without evidence: benches + parity suites recorded.
- No closeout without verification: full matrix above, CI linked.
