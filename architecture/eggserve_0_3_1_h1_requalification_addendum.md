# EggServe 0.3.1 H1 Requalification Addendum

Date: 2026-09-25. Re-runs the closed Phase 73 gate
(`architecture/eggserve_0_3_h1_compatibility_matrix.md`, which stays intact
as the 0.3.0 record) against the newer exact published artifact below.
Production remains on Hyper H1; no production dependency was added.

## Candidate and baseline

- SynVoid baseline: Phase 73 re-run; `crates/synvoid-config/src/http.rs`
  validation ranges confirmed unchanged (`max_request_size >= 8192` with no
  upper bound; `1 <= max_headers <= u32::MAX`; `max_header_size_ingress >= 1`
  with no upper bound), per-site `date_header`/`date_jitter_seconds`/
  `server_token` still present, canonical post-parse ingress enforcement
  still in `crates/synvoid-http/src/request_preparation.rs`.
- Registry query date: 2026-09-25 (`cargo info` + crates.io API).
- Exact artifacts (SHA-256 verified against both the registry API and the
  downloaded `.crate` archives):

| Crate | Version | SHA-256 | Rust requirement |
| --- | --- | --- | --- |
| `eggserve-server` | `0.3.1` | `987b5873f0273b4d02f81f8e19613c93825803c224e972c86e9e9888098f3de8` | 1.89 |
| `eggserve-primitives` | `0.2.1` (unchanged) | `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101` | 1.89 |

- Upstream VCS for 0.3.1: `dc39fef20dd658755ef268c4cd82916448fa3da1`.
- 0.3.0 → 0.3.1 source diff touches only the two hard-blocker areas
  (`src/config.rs`, `src/runtime_limits.rs`,
  `src/connection/{pipeline,request,response,activity}.rs`, `src/lib.rs`,
  `src/response.rs`, tests, README). `src/adapters.rs` and the dependency
  set are byte-identical apart from the version bump: same direct-leaf
  profile (`hyper`, `hyper-util`, `http`, `http-body`, `bytes`, `tokio`;
  optional `http`/`tower-service`/`tower-layer`), no core/static/PHF.

## Workstream C — mandatory range compatibility: CLEARED

- `max_buf_size`: the `<= 4 MiB` validation was deleted; only `>= 8192`
  (Hyper minimum) remains (`src/runtime_limits.rs`). The old constant is
  relabeled "legacy conservative parser-buffer guidance (4 MiB); not a
  runtime maximum."
- `max_headers`: the `<= 10,000` validation was deleted; only `> 0`
  remains. Old constant relabeled likewise.
- Both values project straight into Hyper's builder with only a floor
  clamp (`src/connection/driver.rs`), so SynVoid's full valid range is
  representable at the Hyper layer.
- `max_header_bytes` keeps its 1 KiB–1 MiB scalar validation, but the new
  `H1ConnectionPolicy::with_request_header_bytes_owner(External)` makes the
  pipeline pass `None` instead of the ceiling
  (`src/connection/pipeline.rs`), transferring aggregate-header enforcement
  to the embedder. SynVoid's canonical post-parse check is the ready
  authority. Hyper's own `max_buf_size`/`max_headers` parsing bounds stay
  active under External (upstream test proves a 431 with the service never
  called). The scalar still needs an inert placeholder (e.g. default
  32 KiB) — behaviorally dead under External, recorded here.

## Workstream D — per-site response metadata authority: CLEARED

- New `ResponseMetadataOwnership { date, server }` plus
  `with_response_metadata_ownership()` (`src/config.rs`). With both
  `External`, service responses preserve a valid single `Date`, `Server`,
  or intentional absence **per response**; runtime-generated responses stay
  EggServe-owned (`src/connection/response.rs`, `finalize_runtime_response`
  with `ResponseProvenance`).
- Fail-closed edges (all upstream-tested): invalid or duplicate `Date`
  falls back to a 500 via the error policy; a `server` denylist entry
  still strips even under External; future `Last-Modified` is still
  dropped against the external `Date`. SynVoid-side consequences: emit
  exactly zero-or-one valid `Date` per response, and never denylist
  `server` while external.

## Unchanged dispositions (reconfirmed on 0.3.1 source)

Handler/body/idle/write deadlines (`H1PolicyOwnership::External`),
service/tunnel admission (`AdmissionOwnership::External`), disabled total
connection lifetime, origin-form-only targets, caller-owned
Tokio-stream seam, and the deprecated request-line key (still no safe
projection; `max_request_target_bytes` still 128–64 KiB) are unchanged.
The new ownership fields default to EggServe-owned (additive; upstream
test `h1_policy_ownership_overrides_are_additive_and_default_to_eggserve`).

## Executable evidence

Upstream 0.3.1 suite run locally from the registry archive
(`cargo test --features tower,http-interop -- --test-threads=1`):
**all green** — 94 lib + 2 axum_tower + 14 downstream_embedding + 16
interop + 10 tunnel + 4 doctests, 0 failed. Directly on point:
`parser_values_above_legacy_guidance_validate_and_zero_bounds_fail`,
`parser_guidance_constants_are_not_validation_maxima`,
`direct_h1_external_header_bytes_policy_reaches_service_above_default_ceiling`
(4 MiB+ header bytes with 10k+ fields reaches the service),
`external_header_bytes_policy_keeps_hyper_header_count_limit_active`,
`external_service_metadata_is_preserved_per_response_and_absence`,
`direct_h1_external_response_metadata_is_per_response_and_preserves_absence`,
`direct_axum_response_metadata_survives_external_ownership`.
(One parallel-mode flake in `range_file_body_stops_at_range_boundary`;
`adapters.rs` is identical between releases and the test passes
single-threaded and in isolation — not a regression.)

SynVoid-side E–H prototypes (all passing 2026-09-25):
`crates/synvoid-http/tests/eggserve_0_3_1_qualification.rs` — 28/28
under both `cargo test` and `cargo nextest run -p synvoid-http
--cargo-profile ci --profile ci` (test-only
`eggserve-server = "=0.3.1"` / `eggserve-primitives = "=0.2.1"`
dev-dependencies; no production route changes):

- E (`body_adaptation`, 10 tests): `RequestBody` → `http_body::Body`
  adapter through the existing `StreamingWafBody` machinery — empty,
  fixed Content-Length, multi-frame order, chunked/unknown-length,
  trailers-after-completion, transport-error mapping, early-drop
  abandonment, SynVoid-limit-wins over a non-preempting `Stream`
  policy, narrow-EggServe-limit preemption (counter-case: why production
  must use non-preempting `Stream` + `External` ceiling), mid-stream WAF
  block, plus the `H1PolicyOwnership` production-shape selection.
- F (`tunnel_capability`, 7 tests): live loopback 101 handshake with the
  RFC 6455 accept vector, subprotocol preservation, immediate
  post-upgrade read-ahead echoed exactly once, and decline → ordinary
  HTTP — on **both** `serve_http1_connection_with_policy` (caller-owned
  TCP) and a Hyper H1 server, sharing one neutral handshake assertion;
  plus one-shot accept (consuming, 101), forbidden-framing rejection,
  and the neutral-decision unit contract. SynVoid-owned
  `validate_websocket_upgrade` gates acceptance on both paths.
- G (`connection_drop`, 2 tests): token clone/idempotent/
  level-triggered semantics, and live WAF-Drop order — terminal 403
  selected first, full bytes committed (content-length satisfied, no
  truncation), then EOF with exactly one response on the wire.
- H (`response_stream`, 9 tests): converter preserves status/headers
  (including duplicates and Date/Server/Set-Cookie/CSP/cache/Alt-Svc);
  empty → `Empty`; fixed → `Bytes`; unknown-length → lazy `Stream`
  (zero polls during conversion); known-length → `Stream` with length;
  trailers cross via the trailer future; upstream termination surfaces
  as a sanitized stream error; HEAD/204/304 drop bodies without polling.

Repository verification after recording this decision (`cargo xtask
verify`): **all 10 steps passed** (fmt, clippy, dependency policy, core
compile, repo guards, security regression, root guards, core admin
tests, admin contract, failure injection). `cargo deny check` and the
`--no-default-features` / `mesh` / `dns` / `mesh,dns` / `post-quantum`
compile profiles are green. `Cargo.lock` pins the exact checksums above.

## Decision

`GO_DIRECT_0_3` against the pinned `eggserve-server = "=0.3.1"` /
`eggserve-primitives = "=0.2.1"` artifacts:

- full valid SynVoid H1 parser/header config range preserved (C);
- per-site Date/Server behavior preserved via external metadata
  ownership (D);
- no duplicate deadline/admission authority (additive, EggServe-default);
- body/WAF semantics preserved with SynVoid as size/WAF authority (E);
- WebSocket/app-server tunnel parity proven on both transports (F);
- response streaming preserved without buffering (H);
- request-drop/drain behavior preserved (G);
- caller-owned TCP seam proven live (F/G); prefixed/TLS transport
  cited from the upstream `downstream_embedding` TLS-embedder suite;
- no core/static/TLS/H2/H3 migration (dependency set identical);
- security/dependency gates green.

Phase 74 is unblocked by this decision but is **not** started here (per
the Phase 73 non-goals). Production remains on Hyper H1 until the
adoption sequence completes.
