# Phase 34 Decision Record: Egress HTTP Ownership and Reusable Library Boundaries

Status: complete (2026-09-16). Plan: `plans/phase_34_reusable_library_boundary_cleanup.md`.
Decision: **Branch 2 — retain `synvoid-http-client`** (evidence below).

## Part A — DNSSEC keystore dependency audit

Every `synvoid-core` use reachable from `crates/synvoid-dnssec-keystore` before this phase:

| Use | Classification | Resolution |
|-----|---------------|------------|
| `keystore.rs`: `synvoid_core::time::current_timestamp_secs()` (rotation/expiry math) | Genuinely generic timestamp primitive; SynVoid application coupling | Moved into the keystore as `src/time.rs::now_secs()` (same fail-to-zero semantics). |
| `key.rs`: `synvoid_core::time::current_timestamp_secs()` (ephemeral-key expiry) | Same as above | Same local helper. |
| `hsm.rs` doc comment mentioning `synvoid_config::dns::HsmConfig` | Doc-only; the facade conversion already lives in `synvoid-dns` | No code change; conversion stays in `synvoid-dns`. |

No DNSSEC protocol vocabulary was misplaced, no test-only convenience leaked
into the API, and no micro-crate was created (the primitive is `std::time`
logic, not a sharing boundary). `cargo tree -p synvoid-dnssec-keystore`
after: no `synvoid-core`, no `synvoid-config`, no root `synvoid` edge.

## Part B — DNSSEC public/reuse surface review

| Requirement | Outcome |
|-------------|---------|
| No raw private-key extraction API | Holds: `SealedSigningKey` exposes `sign()` + public metadata only; `private_key` field is crate-private; covered by `crates/synvoid-dnssec-keystore/tests/keystore_boundary.rs` + repo-guard `dnssec_keystore_boundary`. |
| Opaque HSM handles | Holds: query path sees only the `HsmSigner` trait (`sign`, `get_public_key`, `key_id`). |
| Atomic, permission-checked persistence | Holds: temp-file + fsync + rename; dirs `0700`, private files `0600`; overly-permissive files refused on load (unit-tested). |
| No `synvoid-config` types on the public boundary | Holds: `HsmConfig::from_string_parts` takes plain parts; conversion from site config lives in `synvoid-dns`. |
| No Hickory/mesh/admin/Hyper/Quinn/SQLite deps | Holds: enforced by `dnssec_keystore_dependency_budget` guard. |
| DNSSEC-specific algorithm/digest types | Holds: `Algorithm` (IANA 8/15) + `DsDigestType` (1/2/4). |
| HSM opt-in, fail-closed | Holds: `pkcs11`/`hsm` off by default; `NotCompiled`/empty-path errors, no silent SoftHSM fallback (guard + unit tests). |
| Errors expose no key material | Holds: `KeystoreError` carries typed context strings only; Debug impls redact. |
| Crate-level docs/examples without root coupling | Added: lib.rs documents the dependency budget plus runnable examples for ephemeral signing, persistent lifecycle, and HSM use (3 doctests). |

## Part C — `synvoid-http-client` module classification and moves

| Module | Classification | Disposition |
|--------|---------------|-------------|
| `client.rs` (aliases, `create_*`, `EmptyBody`) | Generic transport | Kept. `is_quictunnel_url` kept as a dependency-free scheme predicate; real QUIC/tunnel dispatch already lives in root `quic_tunnel_dispatch.rs`. |
| `pool.rs` (moka caches, `build_*`) | Generic pool | Kept. Keyed on the neutral `UpstreamTlsConfig`. |
| `tls.rs` (`UpstreamTlsConfig`, root loading, `HostnameSkippingVerifier`) | Generic TLS/client policy | Kept **minus** `upstream_tls_from_site_config`, which moved to `synvoid-upstream::tls_adapter` (with its tests + one new defaults test). |
| `request.rs` / `response.rs` (helpers, `HttpResponse`, size limits) | Generic transport | Kept. |
| `erased_pool.rs` (type-erased H1 pool) | Generic transport | Kept. |
| `unix.rs` (hyperlocal client/helpers) | Unix-socket transport | Kept (retained capability; parity-tested; no active production caller today). |
| `streaming_waf_body.rs` | WAF adapter + SynVoid metric | **Moved** to `synvoid-http::streaming_waf_body` (with the `synvoid.http.streaming_body_blocked` metric, which belongs in the domain layer). Narrow `StreamingWafScanner`/`StreamingWafDecision` contract stays in `synvoid-core`; `synvoid-http::shared_handler` now re-exports it from there. |

Net dependency effect (`cargo tree -p synvoid-http-client --depth 1`):
before `synvoid-config`, `synvoid-core`, `metrics` present; after all three
are gone. `synvoid-upstream` gains `synvoid-config` (adapter owner);
`synvoid-http` gains `synvoid-upstream` (call sites already lived there).
No new generic HTTP crate was created. Internal callers migrated:
`upstream_proxy_dispatch_plan`, `streaming_waf_upstream_dispatch`,
`http3_streaming_upstream_dispatch`, `streaming_request_pass`,
`http3_body`, `http3_route_dispatch`, root `http_client` shim.

## Part D — Egress capability matrix (production consumers)

H = synvoid-http dispatch layers, P = synvoid-proxy, U = synvoid-upstream
health, G = synvoid-geoip updater, Y = synvoid-upload rule feed,
N = synvoid-honeypot AI responder, A = synvoid-app-server granian,
R = root (waf feeds, tls/http servers, quic-tunnel dispatch).

| Capability | H | P | U | G | Y | N | A | R | Notes |
|------------|---|---|---|---|---|---|---|---|-------|
| HTTP/1.1 | x | x | x | x | x | x | x | x | All consumers. |
| HTTP/2 (ALPN, upstream) | x | x | - | - | - | - | - | x | `enable_all_versions`; erased path threads `is_http2`. |
| HTTP/3 egress | - | - | - | - | - | - | - | - | H3 is inbound-only (`synvoid-http3` server); upstreams stay H1/H2. |
| Native + WebPKI roots | x | x | x | x | x | x | x | x | Native first, WebPKI fallback, in transport. |
| Custom CA bundle | x | x | - | - | - | - | - | - | Per-site `ca_cert_path`. |
| PQ rustls (aws-lc-rs + prefer-post-quantum) | x | x | x | x | x | x | x | x | Via `post-quantum` feature; unified with `synvoid-tls`. |
| Unix-domain-socket HTTP | retained | - | - | - | - | - | - | - | No active production caller; kept + parity-tested. |
| Streaming request/response bodies | x | x | - | - | - | - | x | x | Raw `Incoming` + generic `B: Body` paths. |
| Type-erased pooled clients | x | x | - | - | - | - | - | x | `ErasedHttpClient` H1 pool; 1M-RPS boxing rationale in skill docs. |
| Per-request timeout / size limits | x | x | x | x | x | x | x | x | `tokio::time::timeout` wrappers; `Limited` bodies. |
| Forward-proxy support | - | - | - | - | - | - | - | - | Not required by any consumer. |
| Cancellation / drain | x | x | x | - | - | - | - | x | Timeouts + task ownership; drain at server layer. |
| Pool controls (idle/size/TTL) | x | x | x | - | - | - | - | x | moka caches (100 entries/300s TTL) + registry. |
| Observability hooks | x | x | x | - | - | - | - | x | tracing in transport; metrics in domain layers (post-Phase-34). |
| Retry semantics | x | x | - | - | - | - | - | - | Owned by `synvoid-proxy::retry`, not transport. |
| Tunnel/QUIC special cases | x | x | x | - | - | - | - | x | `quictunnel://` predicate in transport; dispatch in root; `QuicTunnelStream` in upstream (not HTTP/3 egress). |
| Basic-auth helpers | - | - | - | x | - | - | - | x | `get/head_with_auth` (GeoIP, waf feeds). |
| JSON POST helpers | - | - | - | - | - | x | - | x | `post_json*` (honeypot AI, integration tests). |
| skip-verify w/ audited reason | x | x | - | - | - | - | - | - | Chain-validated, hostname-skipped, reason-logged. |

`synvoid-app-handlers` declares the dep but has no direct `synvoid_http_client::`
use (transitive/reserve); `synvoid-http3` server uses the plain H1/H2 client.

## Part E — `eggfetch-core` 0.1.4 comparison (current release, Sept 2026)

Source: crates.io `eggfetch-core` 0.1.4 metadata + docs.rs feature graph.

| Dimension | `synvoid-http-client` (after Part C) | `eggfetch-core` 0.1.4 | Gap? |
|-----------|--------------------------------------|------------------------|------|
| Protocols | H1 + H2 (ALPN) | H1 + H2; H3 experimental (`http3` feature) | No gap that matters: H3 egress not required (Part D). |
| TLS backend | rustls + aws-lc-rs, `prefer-post-quantum` | rustls via `hyper-rustls` with **`ring`**, `tls12` | **Material**: no aws-lc-rs / PQ knob. |
| Root stores | Native → WebPKI fallback + custom CA file | Native roots + custom CA bundles + mTLS | Parity on roots/CA; mTLS unneeded. |
| Hostname policy | `HostnameSkippingVerifier`: chain-validated, hostname-skipped, reason-audited | Coarse verification toggle | **Material**: adopting regresses the audited skip-verify policy. |
| Unix-socket egress | hyperlocal client + `http+unix`/`unix:` helpers | UDS mentioned only under proxy routes | **Material**: no demonstrated direct-UDS client parity. |
| Body transport | Open: any `B: http_body::Body` (`StreamingWafBody`, `H3ChannelBody`, erased bodies) | Closed `RequestBody` (`impl Into<RequestBody>`) | **Material**: WAF mid-stream scan needs an extension SynVoid may not demand of eggfetch (forbidden branch). |
| Pooling | moka TLS-keyed client cache + type-erased H1 pool | Per-origin pool + phase-aware timeouts | Different semantics; migration buys no reduction (same hyper/rustls stack underneath). |
| Timeouts | Per-request + connect/idle pool controls | Phase-aware (pool/connect/write/read/total) | eggfetch richer, but not required. |
| Proxy/cookies/compression/retry | Not in transport (retry in `synvoid-proxy`) | Built in (forward/CONNECT/SOCKS5, jar, gzip/brotli/zstd, backoff) | No consumer requires these (Part D). |
| Observability | tracing + domain metrics | tracing feature + connector/DNS/TLS/H3 metrics | Rough parity. |
| Error taxonomy | `anyhow` + typed `HttpResponse`; proxy maps to 502s | `thiserror` taxonomy | Mapping cost with zero dep win. |
| Transitive stack | hyper/hyper-rustls/rustls/moka/hyperlocal | hyper/hyper-rustls/rustls (+ connector extras) | **No dependency reduction**: same core stack, one more external owner. |
| MSRV | Workspace (edition 2021; `LazyLock` ⇒ ≥1.80) | 1.80 | Compatible. |
| Maturity | Proven in-workspace transport with parity tests | 0.1.4, days old, ~93 downloads, 3 dependents | **Material**: egress owner would be an unaudited pre-1.0 crate. |

## Part F — Decision (Branch 2: retain)

`synvoid-http-client` is retained because:

1. **PQ gap**: eggfetch is `ring`-pinned with no `prefer-post-quantum`/aws-lc-rs
   path; SynVoid ships PQ preference via the `post-quantum` feature.
2. **Open body transport**: the WAF mid-stream scan (`StreamingWafBody`),
   `H3ChannelBody`, and erased bodies require `B: http_body::Body`
   generality that eggfetch's closed `RequestBody` does not offer, and
   demanding a SynVoid-specific extension is a forbidden branch.
3. **Hostname-scoped verification**: the audited skip-verify policy has no
   eggfetch equivalent.
4. **UDS egress**: no direct-UDS parity demonstrated.
5. **Zero dependency win**: both stacks are hyper/hyper-rustls/rustls; adoption
   adds an external pre-1.0 owner without removing a transitive edge.
6. **Maturity**: 0.1.4 / days-old / ~93 downloads is not an egress foundation
   for a security proxy.

Part C cleanup is complete (generic surface independently testable; config/WAF
coupling removed where feasible). `is_quictunnel_url` stays as a pure scheme
predicate (no tunnel state). No redundant generic HTTP crate was created.

**Future consolidation condition** (revisit only when all hold): eggfetch (or
successor) offers aws-lc-rs/PQ parity, direct UDS egress, an open
`http_body::Body` transport extension, hostname-scoped verification policy,
and a stable, audited release line — plus black-box parity tests proving
equal behavior for every Part D row before any ownership moves.

## Part G — Parity tests

`crates/synvoid-http-client/tests/egress_parity.rs` (hermetic; loopback +
Unix sockets, no external network): H1 keepalive/reuse, H2 over local TLS
with custom CA, invalid-cert failure, timeout expiry, response size limit,
streaming bodies, custom headers, Basic-auth helpers, Unix-socket HTTP, PQ
feature compile behavior, closed-upstream error mapping, pool
saturation/eviction, invalid-URL errors.

## Part H — Dependency and security evidence

- Before: `synvoid-http-client` direct deps included `synvoid-config`,
  `synvoid-core`, `metrics` (see plan record / git history for the full tree).
- After (`cargo tree -p synvoid-http-client --depth 1`): `anyhow`, `base64`,
  `bytes`, `http`, `http-body`, `http-body-util`, `hyper`, `hyper-rustls`,
  `hyper-util`, `hyperlocal`, `moka`, `rustls`, `rustls-native-certs`,
  `rustls-pki-types`, `serde`, `serde_json`, `tokio`, `tracing`,
  `webpki-roots` — no workspace policy crates, no metrics.
- Ownership after: egress TLS + pooling + H1/H2 protocol handling +
  root-store policy = `synvoid-http-client`; site/TLS conversion =
  `synvoid-upstream::tls_adapter`; WAF body adaptation = `synvoid-http`;
  tunnel dispatch = root composition.
- `cargo deny check` / `cargo audit`: clean (mirrors CI `dependency-security`
  job); no new crates added (`rcgen`/`tempfile`/`tokio-rustls`/`hyper-server`
  dev-deps reuse versions already in `Cargo.lock`).
