# Eggfetch 0.2 Transport Consolidation Roadmap

Status: detailed implementation handoff plan (2026-09-22).

Registered in: `plans/roadmap.md`.

Baseline reviewed: `main` at `e3026667c23e6e0e92ee30d13c53baf2e68c5c77` (2026-09-22).

Investigation gate: `plans/eggfetch_current_line_parity_review.md`.

Target upstream: `eggfetch-core 0.2.0`, tag `v0.2.0` (2026-09-22).

## Primary goal

Consolidate SynVoid's generic outbound HTTP transport behind eggfetch 0.2.0 wherever parity is proven, reducing duplicate ownership of Hyper/Rustls/UDS/pooling/timeout machinery without removing or narrowing any existing SynVoid API, protocol, TLS/security behavior, request-body capability, feature profile, or observability contract.

The desired end state is not "replace every type name mechanically." It is:

1. eggfetch owns the reusable transport mechanisms it can satisfy exactly;
2. SynVoid owns policy, compatibility, and application-specific adapters;
3. existing public/re-exported SynVoid paths remain source- and behavior-compatible unless a separate compatibility decision explicitly permits otherwise;
4. legacy transport machinery is deleted only after no supported compatibility surface depends on it.

## Why this campaign is now justified

The Phase 34 decision to retain `synvoid-http-client` was correct for the then-current eggfetch 0.1.4 line, but its material capability blockers are no longer current.

At eggfetch 0.2.0:

- `Client::execute_http_body<B>` accepts arbitrary `B: http_body::Body<Data = Bytes> + Send + 'static`, with `B::Error: Error + Send + Sync + 'static`;
- `NativeHttpService` exposes the same generic-body contract through `tower_service::Service<http::Request<B>>`;
- native responses use a frame-preserving `NativeResponseBody`, including response trailers;
- `TlsConfigBuilder::crypto_provider(...)` accepts an explicit Rustls `CryptoProvider`, allowing SynVoid to supply its aws-lc provider rather than relying on process-global inference;
- certificate-chain verification and hostname verification are separate; eggfetch's `NoHostnameVerifier` keeps chain/signature validation while intentionally skipping name matching;
- `advanced-routing` owns UDS, custom dialing/socket options, SNI override, and resolved/pinned target routing;
- resolved-target clients are cached with route identity that includes logical origin, ordered physical addresses, and SNI override;
- phase-aware timeout machinery covers pool/connect/write/read/total lifecycle;
- MSRV is Rust 1.89, matching SynVoid's current project toolchain direction.

The 0.2.0 release intentionally preserves the 0.1.7 public API/feature graph while synchronizing the registry line and carrying the 0.1.8/0.1.9 fixes, including the streaming decompression chunk-boundary correction.

## Compatibility boundary that must be respected

This campaign MUST distinguish mechanism parity from API identity.

Today `synvoid-http-client` publicly exposes concrete Hyper-based aliases such as:

- `HttpClient = hyper_util::client::legacy::Client<...>`;
- `StreamingHttpClient = hyper_util::client::legacy::Client<...>`;
- Unix client aliases on Unix;
- `ErasedHttpClient`, `ErasedConnectionPool`, `ErasedBodyImpl`, and `BoxErasedBody`;
- the `send_request_*`, `create_*client*`, UDS, response, and TLS helper families.

The root crate also re-exports the crate through `src/http_client/mod.rs`.

Changing an alias to an unrelated wrapper while keeping the same name can still be a source/API break if callers rely on the underlying Hyper type or methods. Therefore:

- do not equate "same exported name" with compatibility;
- do not delete or change a concrete public type identity merely because all in-workspace call sites were migrated;
- Phase 58 must classify the compatibility obligation of every exported symbol before production migration;
- if strict compatibility requires retaining a legacy Hyper facade, retain it as a frozen compatibility lane while moving SynVoid production consumers to the eggfetch-backed lane;
- any later removal/deprecation of a compatibility lane requires its own explicit API-change decision and is outside this campaign.

## Dependency policy

Start with a deliberately narrow eggfetch feature set and expand only from demonstrated need.

Target profile:

```toml
eggfetch-core = {
    version = "=0.2.0",
    default-features = false,
    features = [
        "native-http1",
        "native-http2",
        "tls-rustls",
        "tls-native-roots",
    ],
}
```

Do not enable eggfetch's high-level compatibility bundles merely for convenience. In particular, SynVoid already owns retry and redirect/application policy in higher layers. The native execution path is preferable because it does not implicitly apply redirects, logical retries, cookies, authentication, decompression, or decoded-body policy.

The exact pin is intentional during qualification because 0.2.0 is fresh and pre-1.0. A later Phase 61 closeout may relax it to an ordinary semver requirement only after compatibility evidence exists.

## Rustls provider rule

SynVoid's security contract remains aws-lc/PQ-first.

Every eggfetch TLS client used by SynVoid must receive an explicit provider derived from SynVoid's Rustls/aws-lc configuration. Do not rely on `ClientConfig::builder()` or process-global auto-selection when both Ring and aws-lc may be present.

The campaign must prove:

- the eggfetch client uses the supplied aws-lc provider;
- the `post-quantum` feature still prefers the expected PQ key-exchange group according to SynVoid's existing contract;
- hostname-skip mode still verifies chain/signatures and fails on an untrusted chain;
- custom CA, native-root fallback, SNI override, and normal hostname verification remain equivalent.

Ring already exists in the workspace transitively through QUIC/DNS paths; nonetheless Phase 58 must record the before/after feature graph rather than assuming there is no new duplicate provider state.

## Execution order

### Phase 58 — Eggfetch qualification and compatibility contract

Plan: `plans/phase_58_eggfetch_0_2_qualification_and_compatibility.md`.

Pin and qualify eggfetch 0.2.0 without changing production routing. Re-run the capability matrix, classify the exact compatibility obligation of the existing `synvoid-http-client` exports, prove aws-lc/PQ/TLS/UDS/body/timeout semantics, and record dependency/feature impact.

This phase is a hard decision gate. If a security- or API-critical requirement cannot be met without changing eggfetch or weakening SynVoid, stop and retain the current owner.

### Phase 59 — Eggfetch-backed native transport lane

Plan: `plans/phase_59_eggfetch_native_transport_adapter.md`.

Introduce the private/internal eggfetch-backed transport lane and the neutral conversion layer from SynVoid TLS/pool/timeout policy. Preserve all existing exported APIs. Add black-box parity tests that can run the legacy and eggfetch lanes against the same hermetic fixtures.

No broad consumer migration occurs until the adapter passes parity.

### Phase 60 — Consumer migration and redundant transport retirement

Plan: `plans/phase_60_eggfetch_consumer_migration_and_legacy_transport_retirement.md`.

Migrate production consumers in bounded groups, beginning with leaf/update clients and ending with reverse-proxy streaming paths. Retire only the generic transport machinery made unreachable by the migration. Keep any compatibility lane that Phase 58 proved cannot be removed without an API break.

### Phase 61 — Qualification, performance evidence, and closeout

Plan: `plans/phase_61_eggfetch_transport_qualification_and_closeout.md`.

Run the full parity/security/profile/performance envelope, compare dependency and maintenance surface before/after, adjudicate any compatibility lane that remains, update architecture/current-state docs, and close or roll back the campaign truthfully.

## Global invariants

All phases MUST preserve:

- HTTP/1.1 and HTTP/2 outbound behavior used by SynVoid;
- request streaming without full buffering, including `StreamingWafBody` and H3-originated bodies;
- response streaming and trailer handling;
- existing response-size and timeout failure behavior visible to callers;
- native roots, packaged-WebPKI fallback behavior where currently promised, custom CA files, SNI/server-name override, and audited hostname-skip semantics;
- aws-lc and post-quantum preference behavior;
- UDS capability on Unix;
- existing upstream selection/retry ownership in `synvoid-proxy` / `synvoid-upstream`;
- existing `quictunnel://` handling and tunnel ownership outside eggfetch;
- configuration schema/defaults and feature truthfulness;
- current Prometheus metric names, labels, tracing semantics, and operator-facing errors/statuses;
- bounded pooling/backpressure and no new unbounded queues;
- root and crate public paths unless Phase 58 proves they are private implementation details and the campaign explicitly records that classification.

## Performance and allocation rule

This is primarily a maintenance-consolidation campaign, not a benchmark contest.

Do not accept a transport change that causes an unexplained material regression in the request path merely because it deletes code. Use representative local H1/H2 streaming workloads and existing performance conventions. Treat >5% regression in a primary throughput/tail-latency measure as material until explained.

Pay particular attention to:

- eggfetch logical pool-admission overhead;
- boxed service futures;
- body/frame adaptation;
- client-cache lookup;
- H1 keepalive reuse;
- H2 multiplexing;
- large streaming uploads/downloads;
- cancellation/drop behavior under incomplete bodies.

## Expected maintenance outcome

If parity holds, eggfetch should become the owner of most or all of:

- Hyper client construction;
- H1/H2 connector setup and connection reuse;
- resolved-target route caching;
- UDS transport;
- TLS root loading and client-config construction;
- custom CA plumbing;
- hostname-only verification primitive;
- phase-aware request lifecycle timeout handling;
- native frame-preserving request/response transport.

SynVoid should continue to own:

- site config -> neutral egress policy conversion;
- `allow_plaintext` and other application policy;
- skip-verify reason/audit policy;
- WAF body scanning;
- proxy retry/upstream selection;
- response/error mapping into SynVoid semantics;
- QUIC-tunnel dispatch;
- compatibility facades required by the existing API contract.

## Rejection criteria

Reject or stop the campaign if implementation requires any of the following:

- weakening chain, hostname, SNI, CA, or PQ TLS semantics;
- buffering streaming WAF/H3 request bodies to fit an API;
- moving proxy retry/upstream policy into eggfetch merely because it is available there;
- enabling cookies, automatic redirects, logical retries, or decompression on native proxy transport without a proven existing SynVoid contract;
- changing public concrete aliases or function signatures under the claim that names were preserved;
- removing UDS or retained helper capability;
- introducing a second independent policy model for upstream TLS;
- hiding dependency duplication or Rustls provider ambiguity;
- claiming maintenance reduction while retaining two fully active generic transport implementations;
- deleting the compatibility lane before its callers/contract are explicitly classified.

## Campaign acceptance

The campaign is complete only when Phase 61 records one of two truthful outcomes.

**Adopted:** eggfetch owns the proven generic transport mechanisms, SynVoid production consumers use that path, redundant internal transport code is removed, any retained compatibility lane is narrow/frozen and justified, and all correctness/security/performance gates pass.

**Retained:** a concrete blocker is documented with a failing parity/security/API test or dependency result, production remains on the current transport, experimental adapter code is removed, and current-state docs no longer imply migration is pending without a named condition.

No "mostly migrated" terminal state with ambiguous dual ownership.
