# EggServe 0.3 H1 Adapter Qualification (Phase 75)

Status: **GO for plaintext production migration** (Phase 76 unblocked).
Production remains on Hyper H1/H2; no listener/TLS switch in this phase.

Exact artifacts (pinned `=`, checksums in `Cargo.lock`):

| Crate | Version | SHA-256 | Features in use |
| --- | --- | --- | --- |
| `eggserve-server` | `0.3.1` | `987b5873f0273b4d02f81f8e19613c93825803c224e972c86e9e9888098f3de8` | default off |
| `eggserve-primitives` | `0.2.1` | `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101` | `http-interop` (dependency-free cfg gate for trailer accessors) |

No `eggserve-core`. Reverse consumers: root `synvoid` only
(`src/http/eggserve_h1.rs` + tests), plus the pre-existing test-only
`synvoid-http` dev-dependency from Phase 73. Direct EggServe leaves are
`hyper`, `hyper-util`, `http`, `http-body`, `bytes`, `tokio`,
`futures-util`, `httpdate` — all already in the workspace graph. Root
also gained production `http-body` (narrow frame use in the adapter) and
test-only `synvoid-proxy`/`synvoid-waf`/`httpdate` dev-edges (already in
`Cargo.lock` via the workspace graph).

## Policy projection (`src/http/eggserve_h1.rs::project_eggserve_h1`)

Single projector; no ad-hoc EggServe configuration exists. Constructed
once per server; shared policy/state cross connections.

| SynVoid input | EggServe target | Disposition |
| --- | --- | --- |
| `http.header_read_timeout_secs` | `header_read_timeout` | exact |
| `http.max_request_size` | `max_buf_size` | exact (full range, incl. > 4 MiB) |
| `http.max_headers` | `max_headers` | exact (full range, incl. > 10,000) |
| (none; placeholder default 32 KiB) | `max_header_bytes` | inert (`request_header_bytes_owner = External`; SynVoid `max_header_size_ingress` authoritative) |
| (scalar max 1 GiB) | `max_request_body_bytes` | inert (`global_request_body_ceiling = External`; SynVoid `max_streaming_body_size`/WAF authoritative) |
| handler/body/idle/write/shutdown/keep-alive timeouts, admission numerics, target ceiling | defaults | inert (all ownerships External) |
| (disabled) | `connection_total_timeout = 0` | disabled |
| (origin-form only) | `http1_request_target_mode = OriginOnly` | fixed |
| deadlines/ceilings/admission/metadata | `H1PolicyOwnership`/`AdmissionOwnership`/`ResponseMetadataOwnership` | all External |
| pre-service errors | `SynVoidRejectionPresenter` | fixed `<status> <reason>` bodies, no request data |

Placeholder invariance is proven live: an EggServe lane built with
doubled timeouts, 1 MiB header/body ceilings, and 1024-scale admission
numerics returns byte-identical responses
(`placeholder_invariance_under_external_ownership`).

## Adapter shapes

- `EggserveH1Service<W, D>` (`Service`): `Stream { max_bytes: u64::MAX }`
  body policy (non-preempting); `call_with_tunnel` converts head/body/
  context to `InboundRequest`, wraps the tunnel capability, invokes the
  shared `service_core::handle_neutral_request` (the same function the
  Hyper lane uses after the Phase 75 extraction), converts the response.
  Peer disconnect races the pipeline via the request lifecycle and fails
  closed. Absolute-form targets rejected (400) even though upstream could
  parse them. Non-H1 versions rejected (505).
- Request body bridge: DATA/trailers/errors polled without buffering;
  `Cancelled`/`Disconnected` → neutral `Cancelled`, transport stays
  transport, everything else is a protocol error. Terminal trailers cross
  via the canonical trailer slot.
- Tunnel wrapper: native `accept` with validated headers; `TunnelIo`
  handed over as opaque Tokio IO; decline stays ordinary HTTP.
- Response converter: status/ordered duplicates preserved; exact small
  bodies buffered, empty stays empty, HEAD carries the equivalent-GET
  length as `EmptyWithLength`, larger/unknown streams convert lazily with
  trailer futures on both known and unknown lengths (upstream offers both
  constructors). 8 MiB buffered/streaming threshold, documented.
- Shutdown: per-connection `ConnectionShutdown`; the lane drop callback
  signals it (worker/server drain bridges to the same token at the
  driver in Phase 76). No second idle/total loop.
- `RuntimeState`: one per server instance (projector output); the
  file-stream semaphore is unused by this adapter.

## Canonical correction found by the differential

Upstream-relayed `Date` plus site-generated `Date` both reached the wire
(a spec violation, and EggServe External correctly fail-closes
duplicates to 500). `dedupe_single_value_response_headers` (last wins,
site-authoritative) now runs in `handle_pass_backend_dispatch` for all
H1/H2 responses; unit-pinned. This changes Hyper wire behavior from
"duplicate dates" to "single site date" — approved here as the
correctness fix adoption requires.

## Differential matrix (`tests/eggserve_h1_differential.rs`, 7/7)

Shared neutral pipeline + scripted stub WAF, Hyper H1 vs EggServe lanes:

| Case | Compared |
| --- | --- |
| upstream echo, internal health, small POST, chunked, chunked+trailers, HEAD, dup-CL 400, WAF 403, 1 MiB body | status/headers(multiset)/body |
| per-site metadata (tokens, Date on/off, CSP, cookies, cache, last-modified, date validity) | preservation + validity per lane |
| aggregate 431 (64 B ceiling) | 431 + no-Server + Alt-Svc |
| WAF Drop | identical response; decision counted both lanes; Hyper closure fired; EggServe token fired |
| WebSocket upgrade | 101 + RFC accept + subprotocol, byte-equal |
| keep-alive two-request sequence | both responses byte-equal |
| placeholder invariance | byte-equal across EggServe configs |

Adjudicated normalizations (documented, not waived): header ORDER may
differ (EggServe final boundary vs Hyper send path); `Date` values are
live data (presence/validity asserted per lane). Pinned current
behavior: the response-header filter collapses duplicate `Set-Cookie`
via `insert` — identical on both lanes, correction deferred to a
separate plan.

## Residuals and non-coverage

- Prefixed/TLS streams: plaintext caller-owned TCP proven live; TLS
  convergence is Phase 77 with real Rustls fixtures.
- App-server WebSocket path: handshake parity proven; tunneled traffic
  to a live app-server exercises in Phase 76 production loopback.
- Tarpit/slow-stream responses: converter streams them (no buffering by
  construction); adversarial timing matrix is Phase 78.
- Performance: this phase proves correctness parity only; the same-host
  throughput/latency/RSS comparison is Phase 78 Track G.

## Decision

GO for plaintext production migration under the pinned artifacts and
the projector above. H2/H3/TLS unchanged. Next: Phase 76.
