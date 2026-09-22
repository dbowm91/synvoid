# Phase 58 Plan: Eggfetch 0.2 Qualification and Compatibility Contract

Status: closed. Implemented at `7a6c617cf9dc16441f50da5dcff95778775b5041`; qualification result remains valid. Final campaign closure: Phase 62 proof-bearing `c3568ef4580a49edf222c5e4e6ce5d4dca904e81` (see `architecture/eggfetch_0_2_transport_corrective_closeout.md`).

Roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Baseline: `main` at `e3026667c23e6e0e92ee30d13c53baf2e68c5c77` before campaign planning commits.

Target: `eggfetch-core = 0.2.0` / upstream tag `v0.2.0`.

Depends on: Phase 57 closed; `plans/eggfetch_current_line_parity_review.md` investigation complete enough to open this implementation gate.

## Primary goal

Prove that eggfetch 0.2.0 can satisfy SynVoid's current egress transport and security contracts before any production request path is switched to it, while also defining exactly which `synvoid-http-client` exports must remain source-compatible.

This phase is qualification plus compatibility-contract work. It may add a pinned dependency, private test/adapter scaffolding, and hermetic tests. It must not route production traffic through eggfetch yet.

## Current evidence to verify in-tree

The planning investigation found the following 0.2.0 capabilities and this phase must turn them into executable evidence rather than relying on source inspection alone:

1. generic native request execution via `Client::execute_http_body<B>`;
2. `NativeHttpService` accepting `http::Request<B>` with arbitrary `http_body::Body<Data = Bytes>`;
3. frame-preserving native responses;
4. explicit Rustls `CryptoProvider` injection;
5. separate hostname/certificate verification with chain-preserving hostname skip;
6. UDS under `advanced-routing`;
7. resolved-target routing and route-keyed client reuse;
8. H1/H2 transport and pooling;
9. phase-aware timeout behavior through response-body completion;
10. Rust 1.89 MSRV.

Do not mark a matrix row "parity" only because the method exists. Exercise the behavior SynVoid actually needs.

## Workstream A — Pin the dependency with a deliberately narrow feature profile

Add `eggfetch-core` to the canonical dependency owner for egress transport, initially pinned exactly to 0.2.0.

Use:

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

Do not enable:

- `http3` — SynVoid's outbound requirement is H1/H2; existing H3 ownership is elsewhere;
- `proxy` — not required for current SynVoid egress transport;
- `cookies`;
- compression features;
- high-level redirect/retry policy beyond what the selected native features imply;
- JSON purely to replace SynVoid's simple helper serialization unless evidence shows a real simplification later.

If Cargo feature implications pull policy features unexpectedly, record the exact graph and revise the selected feature set rather than accepting surprise functionality.

Run and preserve evidence from:

```bash
cargo tree -p synvoid-http-client -e features
cargo tree -p synvoid-http-client --depth 2
cargo tree -i ring
cargo tree -i aws-lc-rs
cargo tree -i rustls
```

Record whether eggfetch adds a new version line for Hyper, Hyper-util, Hyper-rustls, Rustls, Tokio, Bytes, HTTP, or HTTP-body. Dependency consolidation does not require zero new package names, but duplicate versions of the foundational transport stack need explicit justification.

## Workstream B — Build a private SynVoid -> eggfetch TLS policy translator

Add a private qualification module under `synvoid-http-client` (name is implementation choice; do not expose a new public contract in this phase) that translates the existing neutral `UpstreamTlsConfig` into eggfetch `TlsConfig` / client construction.

The translator must preserve:

- normal verification;
- custom CA path;
- `server_name` / SNI override semantics;
- chain-validated hostname-skip behavior;
- skip-verify reason kept in SynVoid logging/audit policy rather than passed as generic transport state;
- plaintext permission remaining a SynVoid routing/policy decision, not a TLS toggle hidden inside eggfetch.

For every TLS-enabled client, explicitly pass:

```rust
Arc::new(rustls::crypto::aws_lc_rs::default_provider())
```

or the canonical equivalent already selected by SynVoid. Do not rely on eggfetch's process-provider fallback.

If the `post-quantum` feature changes provider construction, centralize provider selection in one SynVoid helper so legacy and eggfetch qualification paths consume the same authority.

## Workstream C — TLS/security qualification matrix

Extend the existing hermetic egress fixtures rather than creating unrelated integration harnesses.

Required tests:

### Ordinary verification

- locally trusted CA + matching hostname succeeds;
- locally trusted CA + wrong hostname fails;
- untrusted CA fails;
- malformed/empty custom CA fails closed;
- custom CA replacement/fallback behavior is documented and matched to the existing SynVoid promise.

### Hostname-skip mode

Construct a certificate chain trusted by the configured root but intentionally mismatched to the logical hostname.

Prove:

- hostname-skip succeeds for the trusted mismatched chain;
- the same mode fails for an untrusted/self-signed chain not in the trust store;
- normal verification of that mismatched certificate fails;
- logs/audit retain the configured `skip_verify_reason` on the SynVoid side.

This test is security-critical. It proves the adapter is not accidentally equivalent to `danger_accept_invalid_certs(true)`.

### Explicit provider and PQ

Under normal and `post-quantum` builds:

- prove the eggfetch TLS config was constructed with an explicit aws-lc provider;
- prove the relevant SynVoid PQ preference contract remains present;
- if a local TLS handshake can expose negotiated group/cipher information reliably, assert it;
- otherwise assert provider/key-exchange configuration directly and preserve the existing runtime verification mechanism.

Do not install Ring as the process default to make tests pass.

### SNI/server-name override

Exercise the current `UpstreamTlsConfig.server_name` use case:

- TCP logical destination can differ from the certificate/SNI hostname as currently supported;
- the override affects SNI/certificate identity without corrupting Host/authority routing;
- cache reuse never crosses incompatible SNI policy.

## Workstream D — Generic body and frame-parity qualification

Use eggfetch's native path, not `RequestBody::from_stream`, for parity with SynVoid's open body transport.

Test at least:

- `Full<Bytes>`;
- a custom multi-chunk body;
- `StreamingWafBody` around a generic body;
- the H3-originated channel body shape or an exact test-equivalent;
- an erroring body;
- unknown size hint;
- known size hint;
- body cancellation/drop before completion;
- request trailers if any supported SynVoid caller currently emits them;
- response DATA frames;
- response trailers.

The critical acceptance property is no mandatory full buffering and no semantic loss at the native frame boundary.

If eggfetch's native implementation rejects a currently valid body/error type because of stronger trait bounds, determine whether SynVoid can satisfy the bound without changing public behavior. If not, record it as a blocker; do not erase the body error type merely for adoption.

## Workstream E — H1/H2, pooling, resolved target, and UDS qualification

Re-use loopback fixtures from `crates/synvoid-http-client/tests/egress_parity.rs`.

Required behavior:

- H1 keep-alive reuse;
- H2 negotiation and multiplexing;
- connect timeout;
- total request timeout;
- read/body timeout where SynVoid observes one;
- response drop releases logical/physical capacity;
- pool saturation remains bounded;
- same resolved target route reuses connections;
- different logical origin / ordered target set / SNI override does not cross-pool;
- invalid/empty resolved target fails before unintended DNS/network fallback;
- direct UDS request succeeds on Unix;
- UDS remains a truthful unsupported error on non-Unix rather than silently using TCP.

Record semantic differences rather than forcing identical internal counters. The contract is external behavior and bounded resource ownership.

## Workstream F — Public compatibility inventory

Produce a table in a new architecture evidence file, recommended:

`architecture/eggfetch_0_2_compatibility_matrix.md`.

Inventory every public item exported from `synvoid-http-client::lib.rs`, including transitive root re-export paths.

For each item record:

- exact symbol;
- current type/signature;
- whether the underlying concrete type is observable to callers;
- in-workspace production callers;
- root/public re-export status;
- whether implementation can change invisibly;
- whether a compatibility implementation must remain;
- proposed Phase 59/60 disposition.

At minimum classify:

- `HttpClient`;
- `StreamingHttpClient`;
- `UnixHttpClient`;
- `EmptyBody`;
- `ErasedBody` / `ErasedBodyImpl` / `BoxErasedBody`;
- `ErasedConnectionPool` / `ErasedHttpClient` / `PoolKey`;
- `UpstreamTlsConfig`;
- `HttpResponse`;
- all `create_*` functions;
- all `send_request_*` functions;
- UDS helpers;
- `is_quictunnel_url`.

Important: a public type alias to a concrete Hyper client is an API identity, not merely a name. Do not mark it replaceable just because current workspace callers only use a subset of methods.

## Workstream G — Refresh the historical capability matrix

Do not rewrite `architecture/egress_client_decision_phase34.md`; it is historical evidence.

Create `architecture/eggfetch_0_2_compatibility_matrix.md` as the current evidence record containing:

- exact SynVoid baseline SHA;
- exact eggfetch version/tag;
- current capability matrix;
- Phase 34 blockers and their current disposition;
- dependency graph notes;
- compatibility/API notes;
- qualification test results;
- blocker list, if any;
- Phase 59 go/no-go decision.

Update current-state docs that presently say only "pending current-line review" so they point to the new evidence without erasing the historical Phase 34 decision.

## Verification

Focused:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http-client --cargo-profile ci --profile ci
cargo test -p synvoid-http-client --doc --profile ci
cargo xtask test guards
```

Feature/provider:

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
cargo tree -p synvoid-http-client -e features
cargo tree -i ring
cargo tree -i aws-lc-rs
```

Run the broader repository gate if the dependency addition alters the lockfile substantially:

```bash
cargo xtask verify
```

## Acceptance criteria

Phase 58 passes only when:

- eggfetch-core 0.2.0 is pinned with the minimal justified feature set;
- foundational dependency/version impact is recorded;
- explicit aws-lc provider injection works;
- normal TLS, custom CA, SNI override, and hostname-only skip semantics pass;
- hostname-only skip demonstrably still rejects an untrusted chain;
- PQ feature behavior remains truthful;
- generic streaming bodies work without buffering;
- frame/trailer semantics needed by SynVoid are preserved;
- H1/H2 reuse and bounded pool behavior pass;
- resolved-target routing and UDS pass;
- every current public `synvoid-http-client` export is compatibility-classified;
- a current 0.2.0 matrix exists outside the historical Phase 34 record;
- the evidence record gives an explicit Phase 59 go/no-go result.

## Stop conditions

Stop the campaign after Phase 58 and retain the current transport if any required behavior needs:

- weakening TLS verification;
- losing PQ/provider control;
- buffering a required streaming body;
- changing a supported public concrete type/signature with no compatibility path;
- moving higher-level proxy policy into eggfetch;
- adding a new foundational dependency version line that materially worsens the graph without compensating maintenance reduction;
- upstream modifications specialized to SynVoid rather than generally useful eggfetch capability.

A stop is a valid outcome. Remove qualification-only production dependency wiring if the adoption gate fails, preserve the evidence record, and update the roadmap to the retained branch.
