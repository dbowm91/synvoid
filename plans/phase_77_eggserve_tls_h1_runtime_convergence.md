# Phase 77 Plan: EggServe TLS-H1 Runtime Convergence

Status: planned; blocked on Phase 76 closure and green hosted CI.

Registered in: `plans/roadmap.md`.

Parent campaign:
`plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

## Purpose

Route ALPN-selected TLS HTTP/1 connections through the same qualified EggServe
direct H1 runtime used by plaintext, while retaining all SynVoid TLS
termination/security ownership and leaving H2/H3 untouched.

## Frozen TLS ownership

SynVoid remains sole owner of:

- TCP accept/flood checks on the TLS listener;
- Rustls server configuration;
- certificate/SNI selection;
- post-quantum configuration;
- handshake timeout/policy already owned by SynVoid;
- ALPN selection;
- JA4 extraction;
- TLS observability;
- H2 builder/runtime;
- H3/QUIC runtime.

Do not adopt EggServe TLS/listener/core/H3 features.

## Track A — split immediately after completed TLS handshake

Keep the existing Rustls accept path.

After handshake:

```text
TlsStream<TcpStream>
  + negotiated ALPN
  + JA4/connection metadata
       |
       +-- h2 --> existing SynVoid Hyper H2 path unchanged
       |
       '-- H1 --> EggServe serve_http1_connection_with_policy
```

Pass the raw Tokio Rustls `TlsStream` to EggServe. Do not wrap it in
`TokioIo` in SynVoid for the H1 branch.

The H2 path continues using whatever Hyper IO wrapping it currently requires.

## Track B — preserve JA4 and connection metadata

JA4 is computed from SynVoid's TLS handshake context before transport ownership
moves into EggServe.

Thread the resulting JA4 string through the SynVoid service adapter exactly as
the current TLS request handler does.

Do not attempt to reconstruct JA4 from EggServe `TlsInfo`.

EggServe `ConnectionContext` should truthfully identify:

- observed local/remote endpoints;
- HTTPS scheme;
- only TLS metadata that can be represented accurately without inventing
  values.

SynVoid-specific TLS/session metadata remains outside EggServe.

## Track C — remove TLS-H1 duplicate builder

Delete the production TLS-H1 use of:

- `http1::Builder`;
- `configure_h1_builder`;
- `.with_upgrades()`.

The shared Phase 70 H1 policy helper may remain temporarily only if the
test-only legacy differential lane still uses it. It must no longer be a
production policy authority after both H1 paths move.

Do not change the H2 `max_header_list_size` or other H2 builder settings.

## Track D — shared EggServe policy/runtime construction

Plaintext and TLS-H1 must consume the same canonical EggServe policy projector
from Phase 75.

There must not be separate plaintext/TLS mappings for:

- header timeout;
- parser buffer;
- max headers;
- external ownership settings;
- response metadata policy;
- runtime rejection presenter;
- body/tunnel/admission ownership.

Transport context (HTTP vs HTTPS, endpoints, JA4 outside EggServe) is the only
expected per-transport variation.

## Track E — WebSocket over TLS

Exercise real WSS-style inbound upgrade through the completed Rustls stream.

Required:

- real TLS handshake;
- ALPN `http/1.1`;
- WebSocket 101;
- Sec-WebSocket-Accept/subprotocol;
- immediate read-ahead;
- WAF message path;
- upstream WSS/WS routing as configured;
- app-server path;
- graceful shutdown.

This replaces Phase 72's Hyper-H1-over-real-TLS evidence with equivalent
production EggServe evidence; retain Phase 72 as historical baseline.

## Track F — ALPN/H2 negative guards

Add source/behavior guards that prove:

- ALPN `h2` does not call EggServe H1;
- H2 tests remain on existing Hyper H2;
- H2 header-list semantics unchanged;
- no h2c support is added;
- HTTP/3 has no dependency on EggServe server runtime.

## Track G — shutdown/drain

Bridge TLS worker/server shutdown to per-connection EggServe
`ConnectionShutdown`.

Verify:

- idle TLS-H1 closes;
- active response drains according to SynVoid's existing worker semantics;
- active WebSocket/tunnel is terminated/drained;
- no EggServe total/idle deadline fires independently;
- H2 drain behavior unchanged.

## Track H — dependency cleanup checkpoint

After TLS-H1 moves, inspect:

```bash
cargo tree -i hyper
cargo tree -i hyper-util
cargo tree -i tokio-rustls
cargo tree -i rustls
```

Do not remove Hyper merely because H1 no longer uses it. H2 and other modules
still require it.

Identify only H1-specific root imports/helpers now made redundant; defer final
deletion to Phase 78 unless obviously dead and fully guarded.

## Tests

Use real loopback TLS/Rustls fixtures.

Required:

- H1 ALPN control 200;
- H1 slow header timeout;
- H1 max headers;
- H1 parser buffer;
- H1 aggregate 431;
- H1 body/stream/trailers;
- H1 per-site Date/Server;
- H1 WAF Drop;
- H1 WebSocket;
- H1 shutdown;
- H2 control;
- H2 header-limit regression;
- invalid TLS/protocol behavior;
- post-quantum feature compile and existing PQ tests.

## Verification

Run the Phase 76 full matrix plus focused TLS/H2 tests and:

```bash
cargo check --no-default-features --features post-quantum
cargo xtask verify
```

Require hosted CI green for the convergence SHA.

## Acceptance criteria

- [ ] Phase 76 is closed/green.
- [ ] TLS termination/SNI/PQ/ALPN/JA4 remain SynVoid-owned.
- [ ] ALPN H1 uses EggServe direct runtime.
- [ ] ALPN h2 uses existing Hyper H2 unchanged.
- [ ] plaintext/TLS-H1 share one EggServe policy projector.
- [ ] real TLS-H1 parser/body/response/WebSocket tests pass.
- [ ] WAF Drop and shutdown semantics pass.
- [ ] no EggServe TLS/core/H3 dependency is introduced.
- [ ] H2/H3 capability is unchanged.
- [ ] hosted CI passes.

## Non-goals

- No H2 migration to EggServe.
- No H3 migration.
- No TLS stack replacement.
- No PQ redesign.
- No final legacy H1/test cleanup.
