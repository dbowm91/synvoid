# Eggfetch 0.2.1 Patch Adoption Closeout (Phase 102)

Status: **CLOSED QUALIFIED** (2026-10-01).

Final disposition: narrow exact-pin refresh of `eggfetch-core` from `=0.2.0`
to `=0.2.1`. No SynVoid production source change was required; the upstream
0.2.1 release changes only release identity in the `eggfetch-core` manifest
(package version + optional `eggfetch-http-connect` dependency version), and
SynVoid's resolved graph does not pull the optional connector. Production
remains on the in-production eggfetch-backed transport adopted through Phases
58–62.

## Exact versions/checksums

| Crate | Version | SHA-256 (Cargo.lock) | Status |
| --- | --- | --- | --- |
| `eggfetch-core` | `0.2.1` | `826f2baa59cf84f0ba06017685f60065121d69419856a1a57669f184ea7e5b99` | **current production pin** (Phase 102) |
| `eggfetch-core` | `0.2.0` | `6cd254b82aa20d1becb6e3e90a5103e8bcc2d7057bb13532096326e43cd98904` | adoption-era (Phase 58); historical |

Pinned `=0.2.1` in `crates/synvoid-http-client/Cargo.toml` under the existing
narrow feature set (`default-features = false`, `native-http1`,
`native-http2`, `tls-rustls`, `tls-native-roots`). No `eggfetch-http-connect`
package is resolved. No upstream feature was newly enabled. The pin remains
pre-1.0 exact, no semver-range broadening, no workspace-wide loose range,
no `git` dependency.

## Upstream production-source finding

Upstream: `eggstack/eggfetch` `v0.2.1` (2026-09-26). The v0.2.0 → v0.2.1
comparison is 49 commits but the production `eggfetch-core` source is
unchanged. The only production-package changes are release identity in
`crates/eggfetch-core/Cargo.toml`:

- package version `0.2.0 → 0.2.1`;
- optional `eggfetch-http-connect` dependency version `0.2.0 → 0.2.1`.

There are no changes under `crates/eggfetch-core/src/**` between the two
tags. Upstream explicitly records no public API, feature graph/defaults,
MSRV, dependency-policy, or runtime/user-visible behavior change. The
remaining upstream changes are qualification/test hardening, benchmark
harness work, documentation/planning, and coordinated package-version
updates (incl. a new hermetic Windows TLS response-completeness matrix that
is upstream release evidence, not a new SynVoid API contract).

SynVoid enables exactly `native-http1`, `native-http2`, `tls-rustls`,
`tls-native-roots`. SynVoid does not enable eggfetch's proxy feature, so the
upstream `eggfetch-http-connect` version bump does not enter SynVoid's
resolved graph (`cargo tree -p synvoid-http-client -e features` confirms
absence; `eggfetch-http-connect` is not present in `Cargo.lock`).

## Cargo.lock delta (actual)

```diff
 [[package]]
 name = "eggfetch-core"
-version = "0.2.0"
+version = "0.2.1"
 source = "registry+https://github.com/rust-lang/crates.io-index"
-checksum = "6cd254b82aa20d1becb6e3e90a5103e8bcc2d7057bb13532096326e43cd98904"
+checksum = "826f2baa59cf84f0ba06017685f60065121d69419856a1a57669f184ea7e5b99"
 dependencies = [
  "bytes",
  "futures-core",
  "futures-util",
  "h2",
  "http 1.4.1",
  "http-body",
  "http-body-util",
  "hyper",
  "hyper-rustls",
  "hyper-util",
  "pem-rfc7468 0.1.1",
  "pin-project-lite",
  "rustls",
  "rustls-native-certs",
  "thiserror 2.0.20",
  "tokio",
  "tokio-rustls",
  "tower-service",
  "webpki-roots 0.26.11",
 ]
```

One package node (`eggfetch-core`), two lines changed (version + checksum).
No new package nodes. No `eggfetch-http-connect` package. No version drift
in Hyper, Rustls, Tokio, H2, HTTP/body, or any other transport dependency.

Targeted update was produced by:

```text
cargo update -p eggfetch-core --precise 0.2.1
```

## Resolved feature graph

`cargo tree -p synvoid-http-client -e features` resolves only the four
declared eggfetch features (`native-http1`, `native-http2`, `tls-rustls`,
`tls-native-roots`) and their natural intra-crate consequence features
(`advanced-routing`, `standard-route`, `transport-http1`, `transport-http2`,
`hyper-rustls`). No `proxy`, `http3`, `cookies`, `compression`, `json`,
`logical-retry`, or `redirect` feature is enabled. The optional
`eggfetch-http-connect` connector is absent.

`cargo tree -i eggfetch-core` shows `eggfetch-core v0.2.1` is resolved
exactly once via `synvoid-http-client v0.1.0`. No other workspace crate
introduces a second copy of `eggfetch-core` into the resolved graph.

## Production adapter/policy disposition

No SynVoid production adapter or policy code change was required:

- `crates/synvoid-http-client/src/eggfetch_transport.rs` — unchanged.
- `crates/synvoid-http-client/src/eggfetch_policy.rs` — unchanged.
- `crates/synvoid-http-client/src/{client,erased_pool,pool,request,response,tls,unix}.rs`
  — unchanged.
- No change to `UpstreamTlsConfig`, the canonical
  `eggfetch_core::TlsConfig` translator in `eggfetch_policy.rs`, or the
  composition-root wiring in `crates/synvoid-proxy/src/client_registry.rs`.
- The explicit `aws-lc-rs` CryptoProvider remains mandatory.
- Custom CA behavior remains additive; hostname-skip remains
  chain-validating; SNI override remains request-scoped and pool-isolated;
  plaintext allowance remains a SynVoid routing gate.
- The eggfetch lane remains the sole production generic egress transport;
  legacy Hyper helpers remain compatibility/test-only (the
  `eggfetch_lane_freeze_guard` repo guard stays green).
- Outer time-to-headers, connect-only client timeout translation, generic
  streaming request bodies, response frame/trailer preservation, UDS, and
  resolved-target pinning all remain unchanged.

## Qualified feature matrix

The existing Phase 58 qualification, Phase 60 migration parity, and
Phase 62 corrective evidence remain the regression contract and were re-run
on the 0.2.1 artifact:

| Capability | Test target |
| --- | --- |
| Ordinary TLS verification | `eggfetch_qualification.rs::ordinary_verification_*`, `egress_parity.rs::h2_request_with_custom_ca_succeeds` |
| Custom CA | `eggfetch_qualification.rs::*ca*`, `egress_parity.rs::h2_request_with_custom_ca_succeeds` |
| Invalid/untrusted certificate failure | `eggfetch_qualification.rs::untrusted_chain_fails_closed`, `egress_parity.rs::invalid_certificate_fails_closed` |
| Hostname-skip with chain validation | `eggfetch_qualification.rs::{hostname_skip_*,normal_verification_*,wrong_hostname_*}`, `eggfetch_differential.rs::differential_tls_hostname_skip` |
| Explicit `aws-lc-rs` provider | `eggfetch_qualification.rs::explicit_provider_is_present_in_both_modes` |
| SNI override and pool isolation | `eggfetch_qualification.rs::{sni_override_*,sni_policies_do_not_cross_pool}` |
| H1 keepalive | `eggfetch_qualification.rs::h1_keepalive_reuses_single_connection`, `eggfetch_differential.rs::differential_h1_keepalive_reuse`, `egress_parity.rs::h1_keepalive_reuses_single_connection` |
| H2 negotiation/multiplexing | `eggfetch_qualification.rs::h2_negotiation_and_multiplexing`, `eggfetch_differential.rs::differential_h2_tls` |
| Request/response trailers and frame preservation | `eggfetch_qualification.rs::{request_trailers_reach_upstream,response_data_and_trailers_are_frame_preserved}`, `eggfetch_differential.rs::differential_h2_response_trailers` |
| Generic/WAF-shaped / H3-channel-shaped streaming bodies | `eggfetch_qualification.rs::{multi_chunk_body_*,waf_shaped_*,h3_channel_shaped_*,full_bytes_body_roundtrips}`, `eggfetch_differential.rs::differential_waf_shaped_streaming_body` |
| Connect / read / total timeout behavior | `eggfetch_qualification.rs::{connect_timeout_is_bounded,read_timeout_covers_stalled_body,total_timeout_covers_slow_response}`, `egress_parity.rs::configured_timeout_expires` |
| Cancellation / closed upstream / erroring bodies | `eggfetch_qualification.rs::{body_cancellation_before_completion_recovers,erroring_body_surfaces_error_without_panic}`, `egress_parity.rs::closed_upstream_maps_to_error_not_panic` |
| Resolved-target pinning / origin isolation | `eggfetch_qualification.rs::{resolved_target_*,...origins_stay_isolated}` |
| UDS on Unix | `eggfetch_qualification.rs::uds_direct_request_succeeds`, `egress_parity.rs::unix_socket_request_roundtrips` |
| Bounded pooling / saturation behavior | `eggfetch_qualification.rs::{pool_saturation_stays_bounded,response_drop_releases_capacity}`, `egress_parity.rs::{erased_pool_reuses_checked_in_connection,erased_pool_evicts_beyond_max_idle}` |
| Response-size / error mapping | `egress_parity.rs::{response_size_limit_truncates_to_empty,invalid_url_maps_to_error}` |
| Compatibility helper behavior | `egress_parity.rs::http_response_helpers_expose_status_and_headers`, `eggfetch_differential.rs::differential_custom_headers_and_basic_auth` |

The upstream Windows TLS response-completeness matrix added in 0.2.1 is
upstream release evidence; no SynVoid-specific failure was observed, so no
new downstream regression was added.

## Qualification results (this phase)

- `cargo test -p synvoid-http-client --profile ci`: **105 / 105 passed**
  (59 unit + 33 `eggfetch_qualification` + 13 `egress_parity`).
- `cargo xtask test package synvoid-http-client`: **105 / 105 passed**.
- `cargo check -p synvoid-http-client --no-default-features --features post-quantum`:
  clean (no warnings, no errors).
- `cargo check --no-default-features --features post-quantum` (root
  composition): clean.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --profile ci --all-targets -- -D warnings`: clean.
- `cargo check --no-default-features --profile ci` (core compile): clean.
- `cargo test --test security_regression --profile ci -- --test-threads=1`:
  **15 / 15 passed**.
- `cargo nextest run --cargo-profile ci --profile ci …` (root guards,
  `--features mesh`): **647 / 647 passed**.
- `cargo nextest run -p synvoid-core --cargo-profile ci --profile ci …`
  (core admin tests): **16 / 16 passed**.
- `cargo nextest run --cargo-profile ci --profile ci …` (admin contract,
  `--features mesh,dns,icmp-filter`): **66 / 66 passed**.
- `cargo test --test failure_injection --profile ci`: **10 / 10 passed**.

## Dependency-security verification

- `cargo tree -p synvoid-http-client -e features`: `eggfetch-core v0.2.1`
  resolved exactly once; no `eggfetch-http-connect`, `proxy`, `http3`,
  `cookies`, `compression`, `json`, `logical-retry`, or `redirect` feature
  enabled.
- `cargo tree -i eggfetch-core`: resolves exactly once via
  `synvoid-http-client`.
- `cargo deny check`: pre-existing baseline failures remain on the planning
  head — `RUSTSEC-2026-0315` and `RUSTSEC-2026-0316` (wasmtime `call_ref`
  / `catch` fuel accounting and dynamic record lifting) for wasmtime
  `36.0.15` (direct LTS runtime) and `47.0.4` (transitive via the temporary
  `third-party/yara-x-compat` fork of `yara-x 1.20.0`). Both advisories
  exist on the planning head `0dc1f7fb21a5df60e72fc7f2cd60b7cb73bc9f35`
  and are unrelated to the eggfetch patch — the only resolved package that
  changed is `eggfetch-core` (version + checksum). The Phase 102 lock
  update does not introduce a new advisory or denied dependency. The
  wasmtime-line ignore entries remain owned by the routine
  `dependency-security` CI job and the
  `architecture/dependency_security_baseline_phase25.md` re-audit cycle,
  not by Phase 102.
- `cargo audit`: same baseline set (`RUSTSEC-2026-0315`, `RUSTSEC-2026-0316`,
  the six allowed unmaintained warnings). No new vulnerability is
  introduced by the 0.2.1 lock update.
- `deny.toml`: not modified. The two pre-existing ignores
  (`RUSTSEC-2023-0071` rsa-via-yara-x, `RUSTSEC-2026-0235`
  rkyv-0.7-via-minify) and the manifest-only `third-party/yara-x-compat`
  fork remain authoritative.

## Proof-bearing SHAs

- Planning baseline: `0dc1f7fb21a5df60e72fc7f2cd60b7cb73bc9f35` (2026-09-29,
  M003 telemetry corrective closeout head).
- Planning registration: `9e66a0e6` (`plans: phase 102 eggfetch 0.2.1
  patch adoption`) and `02e4c6b9` (`plans: register Phase 102 eggfetch 0.2.1
  adoption`).
- Proof-bearing implementation SHA:
  `2f207c8a4c6a9626e8ce239a037c9c33369b6594` (`egfetch-core: bump
  0.2.0 -> 0.2.1 exact refresh, Phase 102 qualification re-ran`); this
  commit contains the code changes (Cargo.toml pin + Cargo.lock delta +
  qualification-suite preamble reword) and the plan/roadmap status updates.
- Closeout commit (this document): see the next entry on main.
- Hosted CI / native qualification: not invoked for Phase
  102 — the patch is a narrow exact-pin refresh with no source change and
  no resolved-graph drift; per the plan, no new CI job, no native
  qualification host, and no full benchmark rerun is required.
- Hosted CI / native qualification: not invoked for Phase
  102 — the patch is a narrow exact-pin refresh with no source change and
  no resolved-graph drift; per the plan, no new CI job, no native
  qualification host, and no full benchmark rerun is required.

## Performance disposition

The Phase 63 transport benchmark campaign is not re-run. Reason: v0.2.1
contains no production `eggfetch-core` source change relative to v0.2.0,
SynVoid is not changing adapter code, features, policy translation,
pooling, or request-path structure, and the resolved dependency graph
delta is exactly one package's version + checksum. The accepted Phase 63
concurrent-streaming tail residual
(`stream-concurrent` under synchronized concurrency ≥ 4) is a separate
historical/current performance consideration and is not re-adjudicated by
this patch bump. Performance qualification is reopened only if a
reproducible post-bump regression is observed or the resolved graph
materially changes.

## Historical 0.2.0 evidence preservation

Phase 58–64 evidence remains historical and was **not** rewritten:

- `architecture/eggfetch_0_2_compatibility_matrix.md` (0.2.0 evidence).
- `architecture/eggfetch_0_2_transport_closeout.md` (0.2.0 evidence).
- `architecture/eggfetch_0_2_transport_corrective_closeout.md` (Phase 62
  0.2.0 evidence, performance superseded by Phase 63).
- `architecture/eggfetch_0_2_transport_performance_requalification.md`
  (Phase 63 0.2.0 performance evidence).
- `plans/phase_58_eggfetch_0_2_qualification_and_compatibility.md` and the
  Phases 59–64 planning/closeout records.

Only current-authority text that asserted the presently resolved
dependency version was updated:

- `crates/synvoid-http-client/Cargo.toml` current-version comment
  (preserved Phase 58 provenance; corrected from `0.2.0` to `0.2.1`).
- `crates/synvoid-http-client/tests/eggfetch_qualification.rs` preamble
  (reworded to "established for Phase 58 against `=0.2.0`, retained as
  the regression contract for the current qualified `0.2.x` exact pin
  (currently `=0.2.1` since Phase 102)").
- `plans/roadmap.md` Phase 102 status line (closed qualified; terminal
  closeout reference).
- This document.

`plans/phase_102_eggfetch_0_2_1_patch_adoption.md` is updated from
`ACTIVE / READY FOR IMPLEMENTATION` to `CLOSED QUALIFIED` with this
closeout as the terminal authority.

## Future plans / unblocking

No registered SynVoid plan was found blocked on Phase 102. The Phase 102
plan itself is the only `ACTIVE` plan at planning registration, and no
follow-up or downstream plan registers dependency on this exact-pin
refresh. The pre-existing research disposition ("no independently
supported public `synvoid-http-client` until the current eggfetch line is
re-evaluated") is unchanged: Phase 102 is a patch adoption and does not
authorize a publication decision.

The post-Phase-101 architecture maintenance campaign closed with the
recorded residual candidates (mesh-consensus DEFER, process-manager/IPC
DEFER, synvoid-filter RETAIN) and these are not implicitly authorized or
unblocked as implementation work by this closure.

The pre-existing wasmtime-line RUSTSEC-2026-0315 / RUSTSEC-2026-0316
advisories are not in scope for Phase 102 (no eggfetch-related dependency
introduces them; both predate this patch) and remain owned by the routine
`dependency-security` CI job / daily schedule and the Phase 25 dependency
security baseline re-audit cycle.

## Final qualification ledger

| Command/evidence | Result |
|---|---|
| `cargo update -p eggfetch-core --precise 0.2.1` | One package version + checksum; no transitive ripple. |
| `cargo tree -p synvoid-http-client -e features` | `eggfetch-core v0.2.1` only; no `eggfetch-http-connect`; no proxy/http3/cookies/compression/json/logical-retry/redirect feature. |
| `cargo tree -i eggfetch-core` | Resolves exactly once via `synvoid-http-client v0.1.0`. |
| `cargo check -p synvoid-http-client --profile ci` | Clean. |
| `cargo check -p synvoid-http-client --no-default-features --features post-quantum` | Clean. |
| `cargo check --no-default-features --features post-quantum` | Clean. |
| `cargo test -p synvoid-http-client --profile ci` | 105/105 passed (59 unit + 33 eggfetch_qualification + 13 egress_parity). |
| `cargo xtask test package synvoid-http-client` | 105/105 passed. |
| `cargo test --test security_regression --profile ci -- --test-threads=1` | 15/15 passed. |
| Root guard suite (`cargo nextest run … --features mesh`) | 647/647 passed. |
| Core admin tests | 16/16 passed. |
| Admin contract (`--features mesh,dns,icmp-filter`) | 66/66 passed. |
| `cargo test --test failure_injection --profile ci` | 10/10 passed. |
| `cargo fmt --all -- --check` | Clean. |
| `cargo clippy --profile ci --all-targets -- -D warnings` | Clean. |
| `cargo check --no-default-features --profile ci` | Clean. |
| `cargo deny check` | Pre-existing baseline failures (RUSTSEC-2026-0315/0316 on wasmtime) unchanged; not introduced by this patch. |
| `cargo audit` | Same baseline set; no new vulnerability introduced by this patch. |

Final verdict: **CLOSED QUALIFIED**. The patch adoption is a narrow
exact-pin refresh from `eggfetch-core =0.2.0` to `=0.2.1` with no
production source change, no transitive dependency drift, and no new
advisory. Phase 63 performance evidence and Phases 58–62 implementation
evidence remain the upstream-cited historical authority.