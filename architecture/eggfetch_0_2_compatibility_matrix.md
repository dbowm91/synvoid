# Eggfetch 0.2.0 Compatibility Matrix (Phase 58 evidence)

Status: current evidence record (2026-09-22). This file is the Phase 58
qualification + compatibility contract. It does **not** rewrite
`architecture/egress_client_decision_phase34.md`, which remains the
historical record for the eggfetch 0.1.4 decision (correct at the time).

- SynVoid campaign baseline reviewed: `e3026667c23e6e0e92ee30d13c53baf2e68c5c77`
  (2026-09-22, see `plans/eggfetch_0_2_transport_consolidation_roadmap.md`).
- SynVoid implementation baseline: `7083f339a43dd13d6c8f65e7acc9d03ee555b6ef`.
- Upstream reviewed: `eggfetch-core 0.2.0`, tag `v0.2.0` (released 2026-09-22).
- Toolchain: Rust 1.98.1 (eggfetch 0.2.0 MSRV is 1.89 — satisfied).
- Qualification surface: **native** execution only
  (`Client::execute_http_body<B>`, `NativeHttpService` untouched by SynVoid).
  No high-level redirect/retry/cookie/auth/compression/proxy policy enabled.

## 1. Dependency and feature graph (executed, not inspected)

Pin (canonical owner: `crates/synvoid-http-client/Cargo.toml`):

```toml
eggfetch-core = {
    version = "=0.2.0",
    default-features = false,
    features = ["native-http1", "native-http2", "tls-rustls", "tls-native-roots"],
}
```

Deliberately off: `http3`, `proxy`, `cookies`, compression, `json`,
high-level redirect/retry (`http1`/`http2` bundles), `multipart`.
`native-http1` / `native-http2` each imply `transport-http*` +
`standard-route` + `advanced-routing` (UDS, SNI override, resolved targets);
no `high-level-url`/`url` dependency is pulled.

Direct deps of `synvoid-http-client` after the pin
(`cargo tree -p synvoid-http-client --depth 2`): anyhow, base64, bytes,
`eggfetch-core 0.2.0`, http, http-body, http-body-util, hyper, hyper-rustls,
hyper-util, hyperlocal, moka, rustls, rustls-native-certs, rustls-pki-types,
serde, serde_json, tokio, tracing, webpki-roots. New leaf names contributed
via eggfetch (all already present in the workspace lockfile, no new
registrations): futures-core, futures-util, h2, pem-rfc7468,
pin-project-lite, thiserror, tokio-rustls, tower-service.

Foundational transport stack — single version lines, no duplication
(`cargo tree -p synvoid-http-client --depth 2`, `cargo tree -i <crate>`):

| Crate | Unified version | Note |
|---|---|---|
| hyper | 1.10.1 | shared with legacy lane |
| hyper-util | 0.1.20 | shared |
| hyper-rustls | 0.27.9 | shared |
| rustls | 0.23.45 | shared |
| tokio | 1.52.3 | shared |
| bytes | 1.11.1 | shared |
| http | 1.4.1 | shared |
| http-body | 1.0.1 | shared |
| http-body-util | 0.1.3 | shared |

Rustls provider multiplicity (recorded, not hidden): eggfetch's `tls-rustls`
enables `hyper-rustls/ring`, so `ring 0.17.14` is now additionally reachable
via `rustls/ring` in the http-client subgraph (previously reachable only via
hickory/quinn DNS/HTTP3/mesh/tunnel paths), alongside `aws-lc-rs 1.18.1`.
Single versions throughout — no duplicate version line. Both providers are
compiled; selection is deterministic because **every** SynVoid eggfetch TLS
client receives an explicit aws-lc `CryptoProvider`
(`has_explicit_crypto_provider() == true`, asserted in tests), never the
process fallback. `cargo deny check` / `cargo audit`: clean at Phase 58.

## 2. Current capability matrix (executable evidence)

Suite: `crates/synvoid-http-client/tests/eggfetch_qualification.rs`
(33 tests, hermetic loopback/UDS fixtures) plus translator unit tests in
`crates/synvoid-http-client/src/eggfetch_policy.rs` (7 tests).

| # | Capability (plan workstream) | Result | Evidence |
|---|---|---|---|
| 1 | Generic native execution `Client::execute_http_body<B>` | **parity** | all body tests below use it directly |
| 2 | `NativeHttpService` generic-body contract | capable, unused | source contract matches; SynVoid needs only `execute_http_body` |
| 3 | Frame-preserving native responses | **parity** | H2 DATA + trailer frames round-trip (`response_data_and_trailers_are_frame_preserved`) |
| 4 | Explicit Rustls `CryptoProvider` injection | **parity** | `explicit_provider_is_present_in_both_modes`; every test client injects aws-lc explicitly |
| 5 | Separate hostname/certificate verification, chain-preserving skip | **parity** | skip-succeeds / skip-rejects-untrusted / normal-rejects-control trio |
| 6 | UDS under `advanced-routing` | **parity (Unix)** | `uds_direct_request_succeeds`; non-Unix returns truthful `Unsupported` (code path cited §5) |
| 7 | Resolved-target routing + route-keyed reuse | **parity** | pin-without-DNS, empty-rejected, port-mismatch-rejected, origins-isolated |
| 8 | H1/H2 transport + pooling | **parity** | keepalive single-connection reuse; H2 ALPN + 8-way multiplexing; 20-way burst bounded |
| 9 | Phase-aware timeouts through body completion | **parity** | connect / total / read-timeout tests; drop-releases-capacity |
| 10 | Rust 1.89 MSRV | satisfied | workspace toolchain 1.98.1 |
| 11 | `Full<Bytes>` body | **parity** | 64 KiB echo |
| 12 | Custom multi-chunk body (known + unknown size hint) | **parity** | echo tests, no buffering assumption |
| 13 | WAF-shaped generic wrapper body | **parity** | `waf_shaped_generic_wrapper_streams_without_buffering` (shape-forward of `StreamingWafBody`; real wiring is Phase 59) |
| 14 | H3-channel-shaped producer body | **parity** | `h3_channel_shaped_producer_body_roundtrips` (mpsc backpressure) |
| 15 | Erroring body | **parity** | surfaces error, no hang/panic |
| 16 | Body cancellation/drop | **parity** | abort + client recovers |
| 17 | Request trailers (announced, RFC 9112 §7) | **parity** | `request_trailers_reach_upstream`; legacy-vs-eggfetch probe showed identical behavior both lanes |
| 18 | SNI override without corrupting authority | **parity** | `sni_override_uses_intended_identity_without_corrupting_authority`; SNI policies do not cross-pool |
| 19 | Custom CA additivity + fail-closed malformed/empty | **parity** | translator unit tests + build-time rejection tests |
| 20 | PQ feature truthfulness | **parity** | explicit provider in both modes; `post-quantum` handshake test (cfg-gated, mirrors existing pattern) |
| 21 | Ordinary verification trio (match/wrong/untrusted) | **parity** | three dedicated tests |

Observed semantic notes (symmetric, non-blocking):

- Plaintext-H1 trailer emission: a hyper-H1 server fixture does not emit a
  response trailer frame for **either** lane (byte-identical); H2 proves
  end-to-end frame preservation. No SynVoid caller currently emits request
  trailers or consumes response trailer frames (repo-wide grep: only mesh
  chunked-trailer caps and proxy-internal vocabulary, unrelated to egress
  wire frames), so trailers are parity-held capability, not active contract.
- Eggfetch pool admission is logical-request (permit) based, distinct from
  Hyper physical idle caps; both are configured intentionally in Phase 59
  (`max_idle_connections_per_host` + `idle_timeout` mapped from SynVoid
  pool inputs; no global concurrency cap introduced).

## 3. Phase 34 blockers and their current disposition

| Phase 34 blocker (0.1.4) | 0.2.0 disposition |
|---|---|
| PQ gap (`ring`-pinned, no aws-lc/PQ knob) | **closed**: `TlsConfigBuilder::crypto_provider(...)` accepts SynVoid's aws-lc provider; `prefer-post-quantum` feature unification unchanged; explicitness asserted |
| Closed `RequestBody` (no open `http_body::Body`) | **closed**: `execute_http_body<B: Body<Data = Bytes>>`; WAF/H3-shaped generics proven |
| Coarse verification toggle (no audited skip) | **closed**: `verify_hostname(false)` keeps chain verification; untrusted-chain rejection proven; reason stays SynVoid-side |
| No direct-UDS parity | **closed on Unix** (native UDS route); truthful `Unsupported` off Unix |
| Zero dependency win (same stack + pre-1.0 owner) | **reduced**: same foundational versions (no duplication), but consolidation removes SynVoid-owned Hyper/Rustls/UDS/pool construction if Phases 59-60 land; 0.2.0 is the current line (2026-09-22), pinned exactly while pre-1.0 |

## 4. Public compatibility inventory (Workstream F)

Source: `crates/synvoid-http-client/src/lib.rs` (re-exported wholesale by
root `src/http_client/mod.rs`). Rule applied: a public type alias to a
concrete Hyper client is an API identity, not merely a name.

| Symbol | Kind | Concrete identity observable? | In-workspace production callers | Root re-export | Phase 59/60 disposition |
|---|---|---|---|---|---|
| `HttpClient` | type alias → `hyper_util::legacy::Client<HttpsConnector<HttpConnector>, Full<Bytes>>` | **yes** | synvoid-http (dispatch layers), synvoid-proxy (registry/dispatch/executor/server), synvoid-upstream (health), synvoid-http3 (server), synvoid-app-server (granian), synvoid-honeypot (ai), synvoid-geoip (updater), synvoid-upload (rule feed), root http/tls servers | yes (`*`) | **freeze**: keep alias + legacy constructors as compatibility lane; production migrates to internal eggfetch lane |
| `StreamingHttpClient` | type alias → `Client<…, BoxErasedBody>` | **yes** | synvoid-http (proxy dispatch plan) | yes | **freeze** (same rationale) |
| `UnixHttpClient` (unix) | type alias → `Client<UnixConnector, Full<Bytes>>` | **yes** | no active production caller (parity-tested capability) | yes | **freeze**; eggfetch UDS lane qualified for internal use |
| `EmptyBody` | concrete struct + `hyper::Body` impl | **yes** | header-only/HEAD paths via helpers | yes | **preserve** (trivial, no reason to churn) |
| `ErasedBody` / `ErasedBodyImpl` / `BoxErasedBody` | trait / struct / alias | **yes** | synvoid-http streaming dispatches (`ErasedBodyImpl::new(StreamingWafBody…)`) | yes | **preserve type identity**; body-erasure stays useful as adapter even after pool retirement (evaluated Phase 60-H) |
| `ErasedConnectionPool` / `ErasedHttpClient` / `PoolKey` | concrete structs | **yes** | synvoid-http streaming paths, root http server (`ErasedHttpClient`) | yes | **preserve API, retire production use** in Phase 60; custom H1 pool is the prime deletion candidate |
| `UpstreamTlsConfig` | neutral policy struct | yes (by design) | synvoid-upstream `tls_adapter`, all `create_upstream_*` callers | yes | **keep as canonical**: both lanes consume it; no second TLS config type (Phase 59 design rule) |
| `HttpResponse` | concrete struct | **yes** | all buffered helper callers + root quic dispatch | yes | **preserve** (buffered path stays distinct from streaming) |
| `create_http_client` / `create_http_client_with_config` / `create_simple_http_client` / `create_upstream_client` / `create_upstream_streaming_client` / `create_unix_http_client` | fns returning concrete aliases | **yes (return types)** | per above | yes | **freeze as shims**; where the return type forces legacy construction, keep it frozen and mark compatibility-only |
| `send_request` / `send_request_with_timeout` / `send_request_with_timeout_and_headers` / `send_request_with_body_and_timeout` / `send_request_with_body_and_timeout_with_limit` / `send_request_with_body_headers_and_timeout` | fns over `&HttpClient` | signature-bound | leaf/background callers | yes | **freeze signatures**; internal delegation only where pooling semantics provably unchanged, else frozen legacy lane |
| `send_request_streaming` / `send_request_streaming_generic` / `send_request_erased_streaming` | fns (generic / erased) | signature-bound | synvoid-http proxy + H3 dispatches | yes | **freeze signatures**; eggfetch native execution behind the same signatures evaluated in Phase 59-D |
| `get` / `get_with_timeout` / `get_with_auth` / `head_with_auth` | convenience fns | no hidden identity | geoip updater, upload feed, honeypot ai | yes | migrate internals freely; keep behavior (auth header, timeout, size/error mapping) |
| `post_json` / `post_json_with_timeout` / `post_json_response` / `post_json_response_with_timeout` | convenience fns | no hidden identity | honeypot ai + tests | yes | same; SynVoid keeps its own JSON serialization (no eggfetch `json` feature) |
| `is_unix_socket_url` / `send_unix_request_with_body` / `send_unix_request_with_timeout` | UDS helpers | signature-bound | no active production caller | yes | **freeze**; internal UDS via eggfetch qualified |
| `is_quictunnel_url` | pure scheme predicate | no | synvoid-http fast path, root dispatch | yes | **preserve** (no I/O, no state) |

No symbol is classified "implementation hidden": every concrete alias is
compatibility-bound. Production migration (Phase 60) must therefore move
call sites to the internal eggfetch lane without renaming or retyping the
frozen surface.

## 5. Qualification test results

- `cargo test -p synvoid-http-client --test eggfetch_qualification --profile ci`:
  **33 passed, 0 failed**.
- Translator unit tests (`eggfetch_policy.rs`): **7 passed** (run with the
  crate suite).
- Existing suite unregressed: full `-p synvoid-http-client` run green
  (unit + `egress_parity` + doctests).
- Feature profiles checked in Phase 58 scope: default build green;
  `--no-default-features` / `post-quantum` / `mesh` / `dns` / `mesh,dns`
  checks run at campaign gates (Phase 61 records the full matrix).
- `cargo deny check` / `cargo audit`: clean (dependency-security parity).

## 6. Blocker list and Phase 59 go/no-go

Blockers: **none**. No required behavior needs weakening TLS verification,
losing PQ/provider control, buffering streaming bodies, changing a public
concrete type, moving proxy policy into eggfetch, or accepting a new
foundational version line. The `ring`/`aws-lc` provider coexistence is
explicit, measured, and mitigated by mandatory provider injection.

**Decision: GO for Phase 59** (single eggfetch-backed native lane behind the
neutral policy model, differential parity before any consumer migration).
If Phase 59 differential parity fails, the campaign stops and this file
remains the retained-branch evidence.

## 7. Phase 59 addendum — native transport lane + differential parity

Status: implemented and green (2026-09-22).

### Lane shape

`crates/synvoid-http-client/src/eggfetch_transport.rs` (crate-private
module; nothing added to the crate public surface or the root re-export
surface):

- `EggfetchUpstreamClient::{build, cached, build_uds, execute,
  send_buffered, send_uds_buffered}` — the internal transport holder.
  `cached` is a per-policy moka registry (100 entries / 300s TTL, mirroring
  the legacy client-cache discipline) whose key **includes the connect
  timeout** (strictly more correct than the legacy `UpstreamClientKey`,
  which ignores it; legacy keying left untouched as frozen behavior).
- `native_options(resolved, timeout_override)` — SNI hint + pinned target
  travel per request, never baked into the shared client.
- `native_to_httpresponse(response, max_size)` — mirrors
  `HttpResponse::from_hyper` exactly (oversize → status + headers + empty
  body, never an error).
- `eggfetch_client_timeout(connect)` — client-level `Timeout { connect }`
  only. Pool/write/read/total are deliberately unset: no new bounding
  behavior; per-request needs travel explicitly.

### Intentional translation table

| SynVoid input | Eggfetch translation |
|---|---|
| `connect_timeout` | client `Timeout { connect }` |
| `pool_max_idle_per_host` | `max_idle_connections_per_host` (physical idle cap) |
| `pool_idle_timeout` | `idle_timeout` |
| per-request `timeout` | `tokio::time::timeout` around execution (time-to-headers, exactly the legacy helper semantic); `"request timed out"` preserved byte-identically |
| `UpstreamTlsConfig` | `upstream_tls_to_eggfetch` + per-request SNI hint; `skip_verify_reason` SynVoid-side only |
| `allow_plaintext` | pre-transport routing gate (`check_plaintext`; UDS-bound clients exempt) |
| logical concurrency caps | deliberately NOT set — neither lane bounds admission |

No SynVoid policy moved into eggfetch: retry, upstream selection/failover,
WAF, cache, auth, compression, redirect, QUIC-tunnel, and mesh policy all
stay above transport; no eggfetch high-level feature enabled beyond the
Phase 58 pin.

### Differential parity results

Harness: `src/eggfetch_differential.rs` (`#[cfg(test)]`, 18 cases). Same
hermetic fixtures execute both lanes; observable results compared:

- H1 GET / POST buffered (32 KiB echo), keepalive (4 requests / 2 accepts
  on one fixture — one pooled connection per lane, since lanes pool
  separately by construction);
- custom headers + Basic auth; 64 KiB→1 KiB size-limit mapping (empty body
  on both); identical timeout message; closed-upstream / invalid-URL /
  plaintext-gate agreement;
- custom CA success; hostname-mismatch + untrusted-chain failures;
  chain-valid skip success + untrusted-skip rejection on both; H2 ALPN on
  both;
- generic / WAF-shaped / H3-channel streaming bodies byte-identical;
- H2 response trailers identical; early-drop recovery on both;
- Unix UDS buffered parity.

Result: all green (nextest: 322 passed across
`synvoid-http-client` + `synvoid-proxy` + `synvoid-http`, 0 failed).

### Incidental legacy corrections (differential-gated, fail-closed)

The harness caught two latent legacy-lane defects; both fixed in
`src/tls.rs` with the compatibility surface unchanged:

1. **Provider ambiguity (panic).** `build_tls_config` fell back to
   `ClientConfig::builder()` (process-global provider) and built the skip
   verifier with `WebPkiServerVerifier::builder()` (process default). With
   ring unified into the graph the default is ambiguous and construction
   **panics**. Both now use the explicit aws-lc provider; the
   version-negotiation error path returns an empty-version, empty-roots
   config (no handshake can succeed) instead of an ambiguous one.
2. **Skip-verify mismatch variant.** `HostnameSkippingVerifier` matched
   only `CertificateError::NotValidForName`, but rustls 0.23's webpki
   verifier emits `NotValidForNameContext` (same meaning + detail) — so
   hostname-skip over real TLS never actually skipped (previously
   unexercised; only construction was tested). Both name-mismatch variants
   are now skipped; every other certificate error still fails. The eggfetch
   lane was unaffected (its `verify_hostname(false)` is provider-level,
   proven in Phase 58).

### Phase 60 handoff: eligible consumers vs frozen surfaces

Migrate in bounded batches, lowest risk first (each batch re-runs owning
crate suites; legacy lane stays available for diagnosis until Phase 61):

1. Leaf updater/feed: `synvoid-geoip` updater, `synvoid-upload` rule feed.
2. Health/background: `synvoid-upstream` health checks.
3. JSON/AI helpers: `synvoid-honeypot` AI responder.
4. App-server/internal: `synvoid-app-server` granian traffic.
5. Buffered proxy: `synvoid-http` buffered + `synvoid-proxy` dispatch paths.
6. Streaming WAF proxy: native generic-body execution (no buffering).
7. H3-originated upstream bridge (outbound H1/H2 only; no eggfetch `http3`).
8. Remaining root/server composition users.

Frozen regardless of migration (Phase 58 §4 — concrete identity is the
contract): `HttpClient` / `StreamingHttpClient` / `UnixHttpClient` aliases,
all `create_*` constructors, all `send_request_*` signatures,
`ErasedBody(All)` / `ErasedConnectionPool` / `ErasedHttpClient` / `PoolKey`
API, `UpstreamTlsConfig`, `HttpResponse`, UDS helpers,
`is_quictunnel_url`. Production must stop *using* the legacy pool/TLS/UDS
machinery; the shims stay compiling, tested, and documented as
compatibility-only. Retirement candidates after proven unreachability:
`pool.rs` caches, `erased_pool.rs` custom pool, legacy `tls.rs`
construction, `unix.rs` hyperlocal construction, and the direct
`hyperlocal`/`moka`/root-store edges the facade no longer needs.

## 8. Phase 60 migration input — eligible consumers vs frozen surfaces

Migrate (lowest risk first; each batch keeps the legacy lane for diagnosis):

1. Leaf updater/feed: `synvoid-geoip` updater (`get/head_with_auth`),
   `synvoid-upload` rule feed (`get_with_timeout`) — buffered GET/HEAD only.
2. Health/background: `synvoid-upstream` health
   (`create_http_client_with_config` + `send_request_with_timeout`).
3. JSON/AI helpers: `synvoid-honeypot` AI responder (`post_json_with_timeout`).
4. App-server/internal: `synvoid-app-server` granian helper traffic.
5. Buffered proxy: `synvoid-http` buffered dispatches + `synvoid-proxy`
   dispatch/executor buffered paths.
6. Streaming proxy: `synvoid-http` streaming dispatches
   (`send_request_streaming_generic` + `ErasedBodyImpl(StreamingWafBody)`),
   root `http/server.rs` erased-client path.
7. H3-originated upstream: `synvoid-http` H3 dispatch layers (same
   outbound H1/H2 lane; inbound H3 untouched; no eggfetch `http3`).
8. Root/server composition: `src/http/server.rs`, `src/tls/server.rs` (feeds),
   `quic_tunnel_dispatch` (predicate only — dispatch stays root-owned).

Frozen regardless of migration (Phase 58 §4 — concrete identity is the
contract): `HttpClient` / `StreamingHttpClient` / `UnixHttpClient` aliases,
all `create_*` constructors, all `send_request_*` signatures,
`ErasedBody(All)` / `ErasedConnectionPool` / `ErasedHttpClient` / `PoolKey`
API, `UpstreamTlsConfig`, `HttpResponse`, UDS helpers,
`is_quictunnel_url`. Production must stop *using* the legacy pool/TLS/
UDS construction; the shims stay compiling, tested, and documented as
compatibility-only.

Retirement candidates after migration (delete only when proven unreachable
by migrated production AND the frozen surface): `pool.rs` client caches,
`erased_pool.rs` custom H1 pool (`ErasedBody*` adapter types stay),
`tls.rs` legacy client-config construction, `unix.rs` hyperlocal
construction, direct `hyperlocal`/`moka`/`rustls-native-certs`/
`webpki-roots` edges where the facade no longer needs them in signatures.
`UpstreamTlsConfig` and helper types stay.

## 9. Phase 60 record — production migration + legacy retirement (done)

All production consumers run on the eggfetch lane
(`synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient`).
Migration order followed §8 (leaf → health → AI → app-server → buffered
proxy → streaming → H3 → root), with per-path legacy-default preservation:

| Consumer | Lane entry | Legacy default preserved |
|---|---|---|
| `synvoid-geoip` updater, `synvoid-upload` yara feed | `get/head_with_basic_auth`, `get_with_timeout` | ambient `https_or_http` (plaintext-allowed) |
| `synvoid-upstream` health | `send_buffered` | ambient pool/client params |
| `synvoid-honeypot` AI responder | `post_json_with_timeout` / `execute` | `create_http_client()` shape |
| `synvoid-app-server` granian | `send_buffered` / `send_uds_buffered` | UDS path via qualified UDS route |
| `synvoid-http` buffered proxy | `send_buffered(..., max=None)` + post-hoc limit→502 | unbounded collect + post-hoc 502 (NOT lane-internal limit, which maps oversize to 200-empty) |
| `synvoid-http` streaming proxy | `execute` → `Response<NativeResponseBody>` | time-to-headers timeout; `{"request timed out"}` |
| streaming-WAF (`synvoid-http`, H3) | `execute` carries `StreamingWafBody` directly (lane needs only `Send`; legacy needed `Sync`) | verifying default when site sets no TLS; untested `PermissionDenied` downcast branch preserved verbatim (dead in legacy too — no behavior claim) |
| H3 buffered | `execute` + plaintext default | ambient client carried no site TLS (resolving it would be a behavior change; out of scope) |
| proxy-cache (`synvoid-proxy` executor/server/dispatch) | `send_buffered` (returns `HttpResponse` directly; `from_hyper` step deleted) / `execute` + `SyncBody` | pool-hint `is_http2` kept as ignored API field (ALPN negotiates); `BoxErasedBody` boundary converted to `Bytes` (no in-repo callers) |
| root servers (`src/http`, `src/tls`) | ambient `HttpClient` + `ErasedHttpClient` threads deleted (ended dead at dispatch) | — |
| operator plane (`src/admin` alerts, `src/waf` feeds) | `crate::http_client::operator_lane_client()` facade adapter | `create_simple_http_client(30s)` params; root ledger entitles only `http, http_client, tls` (`root_dependencies_have_path_entitlement` green) |

Retirement (Workstreams H/I/J/K/L):

- Deleted: registry legacy maps + `get_or_create`/`get_or_create_streaming`,
  all ambient/erased client constructions and threads, erased sends in
  production, `BoxErasedBody` boundary in `synvoid-proxy` server.
- Kept per Workstream K (frozen compat, still compiling + tested):
  `HttpClient`/`StreamingHttpClient`/`UnixHttpClient` aliases, all
  `create_*`, all `send_*`, `ErasedBody*`/`ErasedConnectionPool`/`PoolKey`,
  `UpstreamTlsConfig`, `HttpResponse`, UDS helpers, `is_quictunnel_url`.
- No dependency removals (Workstream J): the frozen compat implementation
  still needs `hyper-util`, `hyper-rustls`, `hyperlocal`, `moka`,
  `rustls-native-certs`, `webpki-roots` in its signatures. Recorded, not
  removed.
- Freeze enforcement: `tools/synvoid-repo-guards/tests/eggfetch_lane_freeze.rs`
  (`eggfetch_lane_freeze_guard`, negative-controlled) — production outside
  `synvoid-http-client` cannot use legacy tokens or the root facade except
  tunnel dispatch / the operator-lane adapter.

Full evidence: `architecture/eggfetch_0_2_transport_closeout.md` (Phase 61).
