# EggServe 0.4.0 Runtime-Owned `Trailer` Head Addendum

Date: 2026-09-25. Binding record for the Phase 79 Finding B dependency-pin
change. It supersedes only the exact-version identity stated in
`architecture/eggserve_0_3_1_h1_requalification_addendum.md`; that document
remains the 0.3.1 range/metadata/ownership record and all of its cleared
workstreams still hold.

## Why the pin moved

Phase 79 Finding B requires that a terminal trailer block reach the H1 wire
where HTTP/1 framing permits it. Under `eggserve-server =0.3.1` that is not
reachable by any SynVoid-controlled path:

1. Hyper 1.10.1 serializes a response trailer block only when the *response*
   head carries `Trailer: <field-names>` before commitment
   (`hyper/src/proto/h1/role.rs` `Server::encode` `header::TRAILER` arm →
   `Encoder::into_chunked_with_trailing_fields`; without it the encoder kind
   stays `Chunked(None)` and `encode_trailers` returns `None` with
   "the trailer header is not set").
2. EggServe 0.3.1 canonical normalization strips `trailer` as hop-by-hop
   (`eggserve-primitives 0.2.1` `is_hop_by_hop_header`) and re-adds nothing.
3. The public API cannot repair this after the fact: `Response::head_mut()`
   clears the `normalized` flag, so a service that adds `Trailer` forces a
   re-normalization that strips it again.

Observed on 2026-09-25 with 0.3.1: `TE: trailers` reached the request head,
`has_response_trailers()` was `true`, no `ResponseTrailerSuppressed` event
fired, and the wire was still
`5\r\nhello\r\n0\r\n\r\n` with no trailer block.

Upstream fixed exactly this in 0.4.0 (Plan 299): `normalize_then_convert_with_h1_trailer_head`
synthesizes a single runtime-owned `Trailer` head field after normalization,
removes the conflicting `Content-Length`, and is gated on
`TE: trailers` + a head-time declaration. `eggserve-primitives 0.2.2` adds
`TrailerDeclaration` plus `ResponseStream::with_declared_trailers` /
`with_known_length_and_declared_trailers`.

This is the "separately justified upstream release" the Phase 79
non-regression constraint allows; a 0.3.1-pinned tree cannot satisfy the
plan's own wire requirement.

## Candidate artifacts

Registry query date 2026-09-25. SHA-256 verified against both the registry
API and the downloaded `.crate` archives (identical to the `Cargo.lock`
checksums):

| Crate | Version | SHA-256 | Rust requirement |
| --- | --- | --- | --- |
| `eggserve-server` | `0.4.0` | `fb601019a2914ae99f264640b66c80496a67b7ea3315fd0809747d4f22327e40` | 1.89 |
| `eggserve-primitives` | `0.2.2` | `78fd797e45a374bfa419bc75f7e497653ce25e24cde0e771cc332e267f18355c` | 1.89 |

Pinned exactly (`=0.4.0` / `=0.2.2`), `default-features = false`, with
`http-interop` on primitives at the root. Toolchain is 1.98.1, above the
1.89 floor.

## Source delta 0.3.1 → 0.4.0

Five files differ; `src/lib.rs` is byte-identical:

| File | Added | Removed |
| --- | --- | --- |
| `src/adapters.rs` | 22 | 2 |
| `src/connection/pipeline.rs` | 90 | 38 |
| `src/connection/response.rs` | 53 | 4 |
| `src/interop.rs` | 53 | 4 |
| `src/tower.rs` | 6 | 4 |

Primitives 0.2.1 → 0.2.2 touches only
`canonical/response.rs`, `response_stream.rs`, `trailers.rs`, `mod.rs`.

Dependency surface: the only runtime change is
`eggserve-primitives 0.2.1 → 0.2.2`; `tower-layer` moved from a `tower`
feature dependency to a dev-dependency. No new runtime leaf is introduced,
so `cargo deny` / `cargo audit` dispositions are unchanged (both exit 0 on
the bumped tree).

`serve_http1_connection_with_policy`, `ConnectionShutdown`, `H1ConnectionPolicy`,
`RuntimeConfig`, `Service`, and `service_fn` keep their 0.3.1 signatures —
the adapter compiles against 0.4.0 without transport changes.

## SynVoid adapter obligations

`src/http/eggserve_h1.rs::convert_response` must supply a head-time
`TrailerDeclaration`, because EggServe suppresses an undeclared H1 trailer
source before polling it:

- **Exact/buffered bodies** — names are taken from the already-collected
  trailer map (`trailer_declaration_from_map`), so the declaration always
  matches what will be emitted.
- **Streaming bodies** — names are taken from the application's own `Trailer`
  response header (`trailer_declaration_from_headers`); invalid tokens are
  skipped and an empty/wholly invalid declaration yields `None`.
- **No trailers** — no declaration; the buffered `ResponseBody::Bytes` /
  `Empty` fast path is unchanged.

A declaration that fails canonical validation falls back to the undeclared
representation rather than emitting a half-declared head.

## Behavioral consequences

- A declared trailer source forces legal chunked framing on H1: the runtime
  removes `Content-Length`, so an exact trailer-bearing response now ships
  `Transfer-Encoding: chunked` plus `Trailer: <fields>` and the terminal
  block instead of `Content-Length` without trailers. Byte-count validation
  still runs inside the stream adapter. Responses without trailers keep
  `Content-Length`.
- Duplicate legal trailer fields are preserved in the canonical block
  (adapter unit test). On the H1 wire Hyper's `encode_trailers` uses
  `HeaderMap::insert`, so repeated trailer names collapse to their last
  value; that is a Hyper encoding property, not a SynVoid or EggServe loss.
- H2/H3 are unaffected: they never needed the H1 `Trailer` negotiation.

## Verification

- `cargo test -p synvoid --lib http::eggserve_h1 --profile ci` (22 tests).
- `tests/eggserve_h1_runtime_corrective.rs` `plaintext_exact_trailer_wire_block`
  and `tls_h1_exact_trailer_wire_block` assert the head-time `Trailer`
  declaration, chunked framing, and the terminal block on plaintext and
  real TLS-H1.
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci`
  (139 tests, includes the Phase 73 qualification prototypes).
- `cargo nextest run` over `eggserve_plaintext_adoption`,
  `eggserve_tls_h1_convergence`, `eggserve_h1_differential`, and
  `eggserve_h1_runtime_corrective` (50 tests).
