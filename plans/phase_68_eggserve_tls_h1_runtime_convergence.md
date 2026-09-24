# Phase 68 Plan: EggServe TLS HTTP/1 Runtime Convergence

Status: not started; gated by Phase 65 `RETAIN_CURRENT_H1`. See `architecture/eggserve_0_2_2_h1_compatibility_matrix.md`.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggserve_0_2_2_h1_runtime_consolidation_roadmap.md`.

Depends on: Phase 67 production plaintext H1 adoption.

Baseline: Phase 67 proof-bearing implementation/qualification SHA.

## Primary goal

Use the same EggServe caller-owned H1 runtime for TLS connections that negotiate HTTP/1.1, while retaining all TLS termination and protocol-selection authority in SynVoid.

HTTP/2 and HTTP/3 remain untouched.

## Required ownership split

SynVoid continues to own:

- TCP accept;
- pre-handshake flood protection;
- strict HTTP-on-TLS-port probing;
- Rustls server configuration;
- certificate resolver and reload;
- SNI;
- client authentication;
- post-quantum preference;
- TLS handshake timeout/policy where currently owned;
- JA4 extraction;
- ALPN selection;
- H2 connection driver;
- H3/QUIC.

EggServe begins only after:

`acceptor.accept(stream).await`

succeeds and ALPN selects HTTP/1.1/non-H2.

Do not enable EggServe TLS features.

## Workstream A — Factor one shared H1 service/runtime composition

The plaintext and TLS-H1 paths must use the same:

- `SynvoidEggserveService`;
- H1 `RuntimeConfig` projection where transport-independent;
- shared request/body/tunnel adapter;
- response conversion;
- body/admission semantics.

Transport-specific context may differ:

- scheme HTTP vs HTTPS;
- TLS metadata;
- JA4;
- Alt-Svc policy;
- local/remote addresses.

Do not fork a second EggServe service implementation for HTTPS.

## Workstream B — Caller-owned TLS stream handoff

After successful Rustls handshake and ALPN decision:

1. retain the existing `tokio_rustls::server::TlsStream<TcpStream>`;
2. construct truthful EggServe `ConnectionContext`;
3. pass the TLS stream directly to `serve_http1_connection`;
4. preserve cancellation/drain behavior;
5. remove the old TLS H1 `hyper::server::conn::http1::Builder` path only after parity.

The direct driver accepts Tokio byte streams; do not unwrap/re-wrap through raw sockets.

## Workstream C — TLS metadata and JA4

Preserve current JA4 behavior exactly unless a separately proven bug forces a correction.

The SynVoid request pipeline currently receives `ja4_hash` as transport metadata. Continue threading it through the existing policy context; do not attempt to reconstruct JA4 from EggServe TLS metadata.

If EggServe `TlsInfo` can be populated truthfully from the completed SynVoid handshake, populate only fields that can be asserted from actual session data. Omit fields rather than fabricating them.

The canonical security authority remains SynVoid.

## Workstream D — ALPN split remains explicit

The branch must remain structurally obvious:

```text
TLS handshake
   |
   +-- ALPN h2 --------> existing Hyper H2 runtime
   |
   +-- HTTP/1.1 -------> EggServe H1 runtime
```

Do not use an auto H1/H2 server builder that obscures the ownership split.

Required tests:

- ALPN h2 still selects the old H2 path;
- ALPN http/1.1 selects EggServe;
- no ALPN follows the existing H1 fallback;
- unsupported/failed handshake behavior unchanged;
- H2 sibling streams and H2-specific limits unchanged.

## Workstream E — Preserve pre-handshake defenses

Keep flood protection before TLS handshake.

Keep the strict plaintext-on-TLS-port probe behavior and metrics.

Do not move those checks into EggServe because EggServe sees only the post-handshake H1 stream on this path.

## Workstream F — Resolve the existing TLS-H1 parser-setting asymmetry

The current TLS H1 path computes header timeout/max-buffer locals but does not apply them to its Hyper H1 builder.

Once TLS H1 moves to EggServe, the same explicit H1 runtime config used by plaintext should enforce the selected parser/runtime bounds.

Treat this as convergence through the new shared runtime, not as permission to change configured values.

Add regression tests proving plaintext H1 and TLS-H1 receive the same transport-independent:

- header timeout;
- max headers;
- request-target/header ceilings;
- parser buffer ceiling;
- body hard ceiling;
- keep-alive idle policy.

Transport-specific TLS handshake bounds remain separate.

## Workstream G — Forwarded protocol and Alt-Svc parity

Preserve:

- `ForwardedProtocol::Https` for TLS requests;
- current trusted-proxy handling;
- current HTTPS Alt-Svc behavior (currently no TLS-local Alt-Svc injection unless another canonical path says otherwise);
- current site routing using the real local address captured before handshake.

Do not let the EggServe scheme/context replace SynVoid's upstream forwarded-protocol policy implicitly. Map it deliberately.

## Workstream H — WebSocket over TLS

Run the full WebSocket qualification over TLS-H1:

- valid upgrade;
- invalid/malformed upgrade;
- app-server proxy;
- upstream proxy;
- WAF inspection;
- handshake headers;
- post-handshake bidirectional traffic;
- peer disconnect;
- shutdown/drain.

The same Phase 66 neutral capability and Phase 67 EggServe tunnel adapter must be used. No HTTPS-specific WebSocket implementation should remain.

## Workstream I — Remove duplicate TLS-H1 connection machinery

After tests prove parity, remove only code made unreachable by the migration:

- TLS H1 Hyper builder/serve_connection branch;
- duplicate H1 service closure construction;
- duplicate H1-specific connection-drop plumbing that EggServe now owns.

Retain:

- H2 builder/service code;
- TLS accept/ALPN;
- TLS-specific connection/session state still required by H2 or JA4;
- any compatibility helper used elsewhere.

Do not perform unrelated TLS cleanup.

## Verification

Focused TLS/H1/H2:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo nextest run -p synvoid-tls --cargo-profile ci --profile ci
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

Security/dependency:

```bash
cargo deny check
cargo audit
```

Broader:

```bash
cargo xtask verify
```

Include local TLS fixtures covering H1, H2 ALPN, cert/SNI behavior, and TLS WebSocket.

## Acceptance criteria

Phase 68 closes only when:

- plaintext and TLS-H1 share one EggServe H1 service/runtime path;
- SynVoid remains TLS termination/ALPN/PQ/JA4 authority;
- H2 remains on the existing runtime with no capability loss;
- TLS-H1 parser/runtime bounds are explicit and aligned with plaintext;
- HTTPS forwarded-protocol/local-address behavior matches current canonical semantics;
- TLS WebSocket behavior passes;
- duplicate TLS-H1 Hyper machinery is removed only where unreachable;
- all supported feature profiles and routine verification pass.

Do not declare the overall campaign closed here; Phase 69 owns immutable adversarial/performance evidence and final deletion/reconciliation.
