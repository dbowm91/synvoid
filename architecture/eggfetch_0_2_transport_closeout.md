# Eggfetch 0.2 Transport Closeout (Phase 61 — adopted branch)

> **Superseded by Phase 62 (2026-09-22).** The production eggfetch migration remains adopted, but this Phase 61 closeout is not the final campaign authority. A post-closeout audit found an outer-registry policy-key collision, silent invalid-TLS-policy fallback, and incomplete performance/full-release evidence. Final authority: `architecture/eggfetch_0_2_transport_corrective_closeout.md` (proof-bearing `c3568ef4`). Preserve the Phase 61 evidence below as historical context. Note: §2's "exactly one site-keyed map" describes the superseded Phase 60/61 registry; the corrective key is (site, TLS policy).

## 1. Revisions and version

- Pre-campaign baseline (`main`): `e3026667c23e6e0e92ee30d13c53baf2e68c5c77`.
- Phase 58–60 migration commit: `7a6c617c` ("eggfetch 0.2 phases 58-60:
  qualify lane, migrate producers, retire legacy transport").
- This closeout (docs only) follows in the same line; proof-bearing HEAD is
  recorded by the commit carrying this file.
- Eggfetch: `eggfetch-core =0.2.0`, features
  `native-http1, native-http2, tls-rustls, tls-native-roots`
  (no `http3`/`proxy`/`cookies`/`compression`/`json`/redirect-retry).
- Toolchain 1.98.1; eggfetch MSRV 1.89 honored by workspace toolchain policy.

## 2. Production transport owner after migration

One active generic transport: the eggfetch lane, owned by
`crates/synvoid-http-client/src/eggfetch_transport.rs`
(`EggfetchUpstreamClient`: `build`/`cached`/`build_uds`/`execute`/
`send_buffered`/`send_uds_buffered`/leaf helpers; `SyncBody`;
`native_to_httpresponse`; `eggfetch_client_timeout`; `sni_hint_for`).
Policy translation (single model, two comparable lanes) lives in
`eggfetch_policy.rs` (`UpstreamTlsConfig` stays canonical; `allow_plaintext`
is a routing gate, not a TLS toggle).

Per-site selection without double pooling: `UpstreamClientRegistry` keeps
exactly one site-keyed map (`lane_clients`); the lane's global
policy-keyed cache shares physical pools underneath (Workstream I).

## 3. Retained compatibility surfaces (Workstream K) and why

Frozen per matrix §4 — concrete identity is the contract, exercised by
`tests/eggfetch_qualification.rs`, `tests/egress_parity.rs`, and the
`#[cfg(test)]` differential harness (`eggfetch_differential.rs`):

- `HttpClient` / `StreamingHttpClient` / `UnixHttpClient` aliases, all
  `create_*`, all `send_*`, `ErasedBody*` / `BoxErasedBody` /
  `ErasedConnectionPool` / `ErasedHttpClient` / `PoolKey`, `UpstreamTlsConfig`,
  `HttpResponse`, UDS helpers, `is_quictunnel_url`.
- They stay because downstream/test code and the qualification evidence
  depend on their concrete types; production no longer constructs them
  (enforced by `eggfetch_lane_freeze_guard`, negative-controlled).
- Not marked deprecated (project API policy permits no user-visible change).

## 4. Deleted legacy machinery (Workstream L)

- Registry legacy maps + `get_or_create` / `get_or_create_streaming`.
- Ambient `HttpClient` + `ErasedHttpClient` constructions and threads in
  `src/http/server.rs`, `src/http/server/accept_loop.rs`,
  `src/tls/server.rs`, `crates/synvoid-http3/src/server.rs`, and the
  `synvoid-http` dispatch contexts.
- Erased sends in all production paths; `BoxErasedBody` boundary in
  `synvoid-proxy` server (converted to `Bytes`; zero in-repo callers).
- Nothing else deleted: deletion required proof of unreachability by both
  migrated production AND the frozen surface, and the frozen surface still
  needs its implementation (pool, erased bodies, TLS construction, UDS).

## 5. Dependency accounting (Workstream D/J)

No dependency removals. The frozen compat implementation still carries
`hyper-util`, `hyper-rustls`, `hyperlocal`, `moka`, `rustls-native-certs`,
`webpki-roots` in its signatures (`cargo deny check` green; `cargo audit`
green with allow-listed warnings only). `cargo tree` re-verification is due
only alongside a future removal.

## 6. TLS / provider / PQ qualification (Workstream B)

- Explicit aws-lc-rs `CryptoProvider` (no process-default panic with
  ring+aws-lc co-linked); `HostnameSkippingVerifier` matches
  `NotValidForName` + `NotValidForNameContext` (chain-preserving skip).
- `post-quantum` feature profile compiles
  (`cargo check --no-default-features --features post-quantum`).
- Translator logs provider/PQ availability at boot
  (`synvoid_http_client::eggfetch_policy` init line observed in supervisor
  boot log).

## 7. Body / streaming / trailer qualification

- `execute<B>` is body-generic: `Full<Bytes>` (buffered), `StreamingWafBody`
  (WAF scan in flight; lane needs only `Send`, looser than legacy `Sync`),
  `H3ChannelBody` (H3 bridge). Responses stream as
  `Response<NativeResponseBody>`; `SyncBody` adapts non-`Sync` bodies for
  boxed responses (same pattern in H1 and proxy-server paths).
- `native_to_httpresponse` mirrors `HttpResponse::from_hyper` exactly
  (oversize/collection-failure → status + headers + empty body).
- Buffered proxy dispatch deliberately passes `max=None` to the lane and
  keeps the post-hoc `apply_response_size_limit` → 502 check: the lane's
  internal limit maps oversize to 200-empty, which would change legacy
  behavior. Documented at the call site.
- Trailers: preserved through `execute_http_body` with no conversion layer
  (no trailer-specific SynVoid policy exists to regress).

## 8. H1 / H2 / pool / UDS / resolved-target qualification (Workstream A/C)

- H1 keepalive + H2 multiplexing via ALPN negotiation (legacy `is_http2`
  pool-hint fields retained as ignored API, documented at each site).
- Pool reuse keyed by full policy (TLS material, pool sizes, timeouts) in
  both the lane cache and the site registry; `invalidate`/`clear` semantics
  preserved.
- UDS through the qualified eggfetch UDS route (`build_uds`,
  `send_uds_buffered`); truthful off-Unix `Unsupported`, no silent TCP.
- Resolved-target/SNI overrides travel per-request
  (`native_options`/`sni_hint_for`), never baked into shared clients.
- Evidence: `eggfetch_qualification` (33 tests), `egress_parity`
  (timeout expiry, custom CA, invalid URL/cert, streaming round-trip, size
  limit), differential harness (18 cases), crate nextests
  (`synvoid-http-client`, `-proxy`, `-http`, `-http3`, `-upstream`: all
  green), 748 root lib tests green.

## 9. Performance qualification (Workstream E) — residual

Not run. Rationale, not a pass claim:

- The perf campaign (Phases 49–57, closed) declared bench
  (`bench_upstream_selection`, `bench_metrics_hotpath`, `bench_buffer_pool`,
  `bench_honeypot_persistence`) focused-local-only, never routine CI; no
  transport bench with a pre-migration baseline exists on an immutable
  revision, and manufacturing after-the-fact "before" numbers would be
  evidence theater.
- The migration preserves call structure (sameBuffered/streaming split,
  same pool topology, same timeout points); no new per-request allocation
  or hop was introduced on the hot path (the erased-box layer was removed,
  not added).
- Residual: run a before/after transport bench on pinned revisions before
  any future latency-sensitive claim. No material regression is *expected*;
  none is *claimed*.

## 10. Failure and cancellation stress (Workstream F)

- `cargo test --test failure_injection --profile ci`: 10/10 green.
- Egress parity covers timeout-expiry, invalid URL/cert, oversize, and
  streaming round-trip; timeout phase/error mapping preserved
  (`"request timed out"`, `TimeoutPhase::Total`).
- `tests/fault_injection_test.rs` (`#[ignore]`, needs built binary + ~20s):
  `test_worker_crash_recovery` fails on macOS dev hosts ("No worker process
  found as child of supervisor") — supervisor↔worker spawn IPC
  (`src/supervisor`, `runtime_launch`), untouched by this campaign
  (request-path-only diff); the worker boots through lane init successfully
  in the same environment. Linux is the primary target and CI arbiter.
  Recorded as environmental, not a product failure.

## 11. Repository / profile qualification (Workstream G)

All run on this line with toolchain 1.98.1, `--profile ci`:

- `cargo xtask verify`: **10/10 steps green** (fmt, clippy `-D warnings`,
  deny, core compile, repo-guards, security regression single-threaded,
  root guards `--features mesh`, core admin, admin contract
  `mesh,dns,icmp-filter`, failure injection).
- Focused nextest: `synvoid-http-client`, `-proxy`, `-http`, `-http3`,
  `-upstream` (326 + 81), `synvoid-repo-guards`, root lib (748) — green.
- Feature profiles: `--no-default-features` with `[]`, `mesh`, `dns`,
  `icmp-filter`, `mesh,dns`, `post-quantum` — all compile.
- `cargo fmt --all -- --check`, `cargo deny check`, `cargo audit` — green.
- Doctests for touched crates — green (none present).
- NOT run: `verify-full` / `verify-release` (release qualification +
  packaging; `verify-release` fails on a dirty tree by design — due at
  release time, not migration closeout), nightly fuzz smokes, DNS
  conformance script (no DNS-path changes beyond the shared lane).

## 12. Documentation reconciliation (Workstream H)

- This file (required closeout record); matrix §9 (Phase 60 record).
- `.opencode/skills/http_client/SKILL.md` + `src/http_client/AGENTS.override.md`:
  lane-canonical ownership, frozen legacy, facade adapter rule.
- `architecture/http_shared.md`: erased-pool sections gain a supersession
  pointer to this closeout (history preserved, not rewritten).
- `plans/roadmap.md`: 58–61 status reconciled to complete.
- Phase 34 / Phase 47 records linked as superseded decision history, not
  rewritten.

## 13. Public-crate disposition (Workstream I)

`synvoid-http-client` stays internal (class 1–2): a SynVoid-specific
compatibility/policy adapter. Eggfetch is the reusable public generic HTTP
client; SynVoid publishes no competing generic transport. The remaining
Hyper-concrete compat surface is an internal compatibility burden, not a
marketing reason. Revisit only with a fresh parity review.

## 14. Disposition (Workstream J) — adopted branch

Adopt the eggfetch lane as the sole production transport. No rollback
trigger fired (no rejection criterion met: no unresolved parity break, no
material measured regression, no security invariant weakened — constant-time
comparison, fail-closed TLS/UDS/policy gates, and audit bounds all
preserved). The legacy lane remains frozen and tested for diagnosis, guarded
against production drift.
