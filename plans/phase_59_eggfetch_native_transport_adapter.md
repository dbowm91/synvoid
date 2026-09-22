# Phase 59 Plan: Eggfetch Native Transport Adapter

Status: implemented at `7a6c617cf9dc16441f50da5dcff95778775b5041`; adapter/differential-parity work remains the production baseline, with final campaign closure pending Phase 62.

Roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Depends on: Phase 58 qualification passes with an explicit go decision in `architecture/eggfetch_0_2_compatibility_matrix.md`.

## Primary goal

Introduce an eggfetch-backed transport implementation inside SynVoid while preserving every existing exported `synvoid-http-client` contract identified by Phase 58.

This phase establishes one production-capable eggfetch lane and proves parity against the legacy lane. It must not yet perform a broad call-site sweep or delete compatibility code.

## Design rule: one policy model, two temporarily comparable transport lanes

Do not fork upstream policy.

`UpstreamTlsConfig`, SynVoid timeout/pool inputs, plaintext permission, SNI override, skip-verification reason, and higher-level retry/upstream policy remain the canonical SynVoid inputs. The legacy and eggfetch lanes must consume the same neutral policy so parity tests compare transport implementations rather than two separately configured systems.

Recommended internal structure:

```text
synvoid-upstream/site config
        |
        v
UpstreamTlsConfig / existing neutral egress inputs
        |
        +------------------------+
        |                        |
        v                        v
legacy Hyper adapter       eggfetch adapter
        |                        |
        +-----------+------------+
                    |
              caller contract
```

The exact module layout is an implementation decision, but do not introduce a second public TLS configuration type.

## Workstream A — Centralize Rustls/provider construction authority

Create one private helper for the provider policy used by both qualification tests and the eggfetch lane.

Requirements:

- aws-lc is explicit;
- PQ preference follows the existing `post-quantum` feature contract;
- no process-global Ring installation;
- the helper is cheap to clone/share;
- provider identity is not accidentally recomputed into incompatible connection pools;
- existing server-side TLS ownership remains outside this adapter unless a tiny shared helper is clearly appropriate.

If existing bare Rustls `ClientConfig::builder()` calls in the same egress boundary depend on process default selection, migrate them to explicit provider construction where necessary to prevent the new ring-enabled feature graph from making provider choice ambiguous. Do not broaden into unrelated TLS-server refactoring.

## Workstream B — Implement neutral TLS conversion

Implement the Phase 58 translator as production-quality private code.

Map:

- `verify = true`, `skip_verify = false` -> normal eggfetch certificate + hostname verification;
- custom CA path -> eggfetch custom trust store semantics matching current SynVoid behavior;
- `server_name` -> transport/SNI override without changing logical HTTP authority;
- `skip_verify = true` -> chain/signature verification retained, hostname match disabled;
- `skip_verify_reason` -> SynVoid audit/logging only;
- `allow_plaintext` -> routing/policy gate outside TLS config.

Fail closed on invalid CA/provider/config construction. Do not silently fall back from a requested custom policy to defaults.

## Workstream C — Add an internal eggfetch client abstraction

Introduce an internal transport holder that wraps/configures `eggfetch_core::Client` and exposes only the operations SynVoid actually needs.

Prefer a narrow internal API around:

- buffered request send;
- native generic-body send;
- client construction with connect/pool/idle/TLS policy;
- per-request timeout translation;
- resolved target/SNI hints if currently needed;
- UDS construction where applicable.

Do not mirror eggfetch's entire API into SynVoid.

Do not make this internal holder part of the root public re-export surface in this phase.

## Workstream D — Request/response adaptation

Implement adapters between current SynVoid helper contracts and eggfetch native responses.

### Requests

For generic/streaming paths, use `Client::execute_http_body<B>` directly.

Do not route `StreamingWafBody`, H3 channel bodies, or erased bodies through a bytes-stream conversion if the generic body path can preserve frames directly.

Preserve:

- method;
- URI;
- headers;
- body size hint;
- trailers;
- request cancellation;
- timeout behavior;
- error provenance needed by current callers.

### Responses

Map `http::Response<NativeResponseBody>` into the shape required by each existing SynVoid caller without eager body collection.

Preserve:

- status;
- headers;
- streaming;
- trailers;
- size-limit enforcement;
- body-drop/cancellation semantics;
- connection/pool lease release.

If the existing `HttpResponse` helper represents a buffered path, preserve that helper separately from raw streaming responses rather than forcing all responses into one abstraction.

## Workstream E — Pool configuration translation

Map current constructor arguments:

- connect timeout;
- `pool_max_idle_per_host`;
- `pool_idle_timeout`;
- per-upstream TLS policy.

Document where eggfetch's model differs from Hyper legacy client settings.

The acceptance requirement is behavioral equivalence at the SynVoid contract, not field-for-field internal equivalence.

If eggfetch has both logical request admission limits and Hyper physical connection pooling controls, configure them intentionally. Do not accidentally introduce a global concurrency limit where SynVoid previously had only idle-pool bounds.

## Workstream F — UDS transport adapter

Use eggfetch UDS support for the new lane.

Preserve current Unix helper behavior:

- socket path selection;
- logical HTTP URI/path;
- request body/header behavior;
- timeout/error mapping;
- non-Unix unsupported behavior.

Keep the legacy `UnixHttpClient` public alias/creator if Phase 58 classified it as compatibility-bound. Production/internal callers may use the eggfetch lane even while the compatibility path remains.

## Workstream G — Differential parity harness

Extend the hermetic egress suite so the same fixtures can execute both:

- legacy Hyper lane;
- eggfetch lane.

Required differential cases:

- H1 GET/POST;
- H1 keepalive;
- H2 TLS;
- normal TLS verification;
- custom CA;
- hostname mismatch failure;
- chain-valid hostname-skip success;
- untrusted-chain failure under hostname-skip;
- headers including auth/custom headers;
- buffered body;
- generic streaming body;
- `StreamingWafBody`;
- H3-originated channel body/test equivalent;
- response size limit;
- timeout;
- closed upstream/error mapping;
- UDS;
- response trailers;
- early response-body drop.

Compare observable results, not private error strings or internal pool counters unless those are part of a current contract.

## Workstream H — Compatibility facade strategy

For every Phase 58 item classified "must preserve concrete identity," keep the legacy public surface unchanged.

For items classified "name/signature only; implementation hidden," delegate internally to the eggfetch lane where possible.

Do not convert a type alias into a wrapper and call it compatible.

Where a compatibility function's exact return type forces construction of the legacy Hyper client, keep that constructor as a compatibility shim and mark it in the compatibility matrix as intentionally retained. Do not route production callers through it merely to justify its existence.

The objective is to make legacy compatibility code cold/frozen, not to delete it dishonestly.

## Workstream I — No policy migration into eggfetch

Explicitly keep these outside the eggfetch adapter:

- SynVoid upstream selection;
- retry policy;
- failover;
- WAF scanning;
- cache policy;
- authentication policy;
- compression policy;
- redirect policy;
- QUIC-tunnel routing;
- mesh policy.

If an eggfetch high-level feature would duplicate an existing SynVoid policy owner, leave it disabled.

## Verification

Focused:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http-client --cargo-profile ci --profile ci
cargo nextest run -p synvoid-proxy --cargo-profile ci --profile ci
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo xtask test guards
```

Profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Dependency/security:

```bash
cargo deny check
cargo audit
```

Broader gate:

```bash
cargo xtask verify
```

## Acceptance criteria

Phase 59 is complete only when:

- a production-capable eggfetch transport lane exists;
- it consumes the existing neutral SynVoid policy model;
- aws-lc provider selection is explicit;
- generic request bodies use eggfetch's native body API without forced buffering;
- response streaming/trailers remain intact;
- UDS works through eggfetch on Unix;
- pool/timeout settings are intentionally translated;
- legacy and eggfetch lanes pass the differential parity suite;
- no current public concrete type/signature identified as compatibility-bound was changed;
- no higher-level SynVoid policy moved into eggfetch;
- no broad production consumer migration has occurred yet;
- Phase 60 has a clear list of consumers eligible for migration and compatibility surfaces that must remain.

## Rejection criteria

Reject this phase if it:

- uses the high-level eggfetch API where native execution is required for frame/body parity;
- buffers streaming request bodies;
- changes public type identity;
- silently broadens retry/redirect/cookie/compression behavior;
- lets eggfetch select a different Rustls provider from SynVoid;
- adds a second TLS policy model;
- weakens UDS/platform behavior;
- claims parity without running both lanes against the same fixtures.
