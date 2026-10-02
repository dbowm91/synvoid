# Phase 111 Plan: SynVoid Tunnel / Eggtunnel / Eggress Convergence

Status: **CLOSED DEFER — cross-repo source and protocol parity unavailable** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline for registration: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).

Owner: tunnel/networking / cross-repo architecture.

Relevant upstream repositories:

- `eggstack/eggtunnel`;
- `eggstack/eggress`.

## Goal

Reduce duplicated generic tunnel/session/relay maintenance in SynVoid by
adopting or upstreaming reusable mechanisms into Eggtunnel/Eggress while
retaining SynVoid-specific route, mesh, VPN, and application semantics locally.

This phase explicitly rejects creating a separate `synvoid-tunnel` repository.

## Current state

`synvoid-tunnel` currently owns:

- QUIC runtime/registry;
- tunnel framing/messages/validation;
- session and port mapping;
- UDP/datagram management;
- upstream resolution;
- TUN;
- WireGuard integration;
- metrics and lifecycle.

`synvoid-vpn-client` consumes SynVoid tunnel framing/messages/runtime directly.
`synvoid-mesh` consumes the SynVoid QUIC runtime.

Eggtunnel already owns an embeddable authenticated tunnel protocol/library with:

- explicit wire version/capability negotiation;
- client/server session lifecycle;
- service registration;
- TCP/TLS transport;
- QUIC transport;
- WSS;
- outbound proxy traversal through Eggress;
- bounded diagnostics/auth/service identifiers;
- relay/drain semantics.

The overlap is material but not complete. SynVoid additionally has UDP/datagram,
VPN/TUN/WireGuard, route/upstream, and mesh-specific semantics.

## Workstream A — build a symbol/capability ownership matrix

Compare current SynVoid tunnel/VPN symbols against Eggtunnel/Eggress.

At minimum classify:

- frame header/versioning;
- auth/session identity;
- registration/mapping;
- connection IDs;
- reconnect/backoff;
- ping/pong/health;
- graceful drain;
- QUIC connection/stream ownership;
- stream relay and half-close;
- TLS policy;
- proxy traversal;
- UDP/datagram;
- TUN;
- WireGuard;
- local listener/VPN behavior;
- upstream URL/route resolution;
- mesh QUIC reuse;
- metrics/diagnostics.

For every row choose:

- **ADOPT Eggtunnel/Eggress**;
- **UPSTREAM generic SynVoid mechanism**;
- **RETAIN SynVoid application semantics**;
- **DEFER** pending capability maturity.

Do not judge by function-name similarity; compare wire/lifecycle/security
semantics.

## Workstream B — preserve wire compatibility

SynVoid and Eggtunnel currently have separate wire contracts.

No migration may silently reinterpret an existing SynVoid tunnel peer as an
Eggtunnel peer.

Choose explicitly:

1. keep SynVoid wire compatibility behind an adapter while using Eggress
   transport/relay mechanics;
2. add a negotiated Eggtunnel-compatible mode;
3. perform a versioned SynVoid protocol migration with backward compatibility.

Any wire change requires golden vectors and mixed-version tests. A crate-version
bump is not a wire-versioning strategy.

## Workstream C — generic QUIC runtime ownership

Audit whether SynVoid's `QuicRuntime` is genuinely tunnel-specific or a
generic mechanism Eggress/Eggtunnel should own.

Prefer Eggress/Eggtunnel ownership for:

- endpoint setup;
- connection acceptance/dial;
- stream open/accept;
- bounded connection lifecycle;
- generic relay/backpressure;
- transport error mapping.

Retain SynVoid-specific peer identity, route authorization, metrics labels and
mesh application dispatch outside the generic runtime.

Do not make Eggtunnel depend on SynVoid mesh.

## Workstream D — UDP/datagram adjudication

SynVoid already has datagram concepts not present in Eggtunnel's current
TCP-service model.

Evaluate whether a generic authenticated datagram capability belongs in
Eggtunnel/Eggress.

If yes:

- write a separate upstream plan in the owning Eggstack repository;
- define negotiated capability IDs/version behavior;
- bound datagram sizes/queues/associations/timeouts;
- qualify replay/session confusion and saturation;
- land/release upstream before SynVoid deletes its generic implementation.

If no, document why the semantics are SynVoid/VPN-specific and retain locally.

Do not tunnel UDP by pretending it has TCP half-close semantics.

## Workstream E — WireGuard/TUN disposition

Keep unfinished or product-specific WireGuard/TUN behavior out of Eggtunnel's
stable protocol unless independently mature.

Classify:

- generic TUN device abstraction;
- generic WireGuard peer/session lifecycle;
- SynVoid VPN configuration;
- mesh/service routing.

Only upstream a mechanism if it has an independent use case and qualification
story. Otherwise retain it as SynVoid/VPN functionality.

## Workstream F — configuration and dependency direction

SynVoid-specific config must remain in SynVoid adapters.

A generic Eggtunnel/Eggress API should accept neutral transport/session policy,
not `synvoid-config`.

The desired SynVoid end state is approximately:

- Eggress: transport/relay primitives;
- Eggtunnel: authenticated tunnel/session protocol and generic client/server;
- SynVoid: config, route/upstream policy, mesh adapter, VPN product semantics.

## Workstream G — cross-repo planning discipline

When the matrix identifies required Eggtunnel/Eggress work:

- register a focused implementation plan in the owning repository;
- include compatibility tests needed by SynVoid;
- do not land a SynVoid local fork of the desired upstream feature as the
  permanent answer;
- pin released versions for final SynVoid adoption where practical.

Cross-repo phases should be independently releasable.

## Workstream H — migration qualification

For each adopted mechanism prove:

- existing SynVoid tunnel behavior remains supported;
- connection/session limits remain bounded;
- auth/TLS semantics do not weaken;
- cancellation/drain/backpressure behavior is correct;
- mesh and VPN consumers remain functional;
- dependency/binary/LOC maintenance burden decreases.

Measure actual removed code/dependencies; wrapper-on-wrapper migration without a
maintenance win is not success.

## Verification

Use both SynVoid and relevant Eggstack repository contracts. SynVoid minimum:

```bash
cargo test -p synvoid-tunnel --profile ci
cargo test -p synvoid-vpn-client --profile ci
cargo test -p synvoid-mesh --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

## Closeout (2026-10-02)

The capability matrix and evidence boundary are recorded in
`architecture/tunnel_convergence_phase111.md`. The Eggtunnel repository/source
was not available in the workspace, and the named repository could not be
located in the local project checkouts. Eggress is available, but its QUIC
crate is an optional proxy/H3 transport and its generic stream relay is not an
authenticated tunnel/session protocol. The evidence therefore does not support
wire/lifecycle parity or a safe migration.

SynVoid retains its existing implementation and wire contracts. No dependency,
protocol, or runtime behavior changed. Do not remove SynVoid framing, datagram,
TUN/WireGuard, route, or mesh paths based on Eggress's proxy transport. This
plan may reopen when Eggtunnel source and its compatibility/security test
contract are supplied or checked out, with exact release/API versions pinned.

Run mixed-version/wire vectors and end-to-end tunnel tests for affected paths.

## Acceptance criteria

- every overlapping tunnel capability has an explicit owner;
- generic transport/session/relay duplication is reduced where parity exists;
- no new SynVoid tunnel repository is created;
- Eggtunnel/Eggress do not acquire SynVoid application dependencies;
- UDP/WireGuard/TUN are upstreamed only when genuinely generic and qualified;
- wire compatibility is explicit and tested;
- SynVoid's resulting tunnel crate is primarily application/policy integration.

## Rejection criteria

Reject implementation that:

- replaces one duplicate with a permanent SynVoid fork of Eggtunnel/Eggress;
- breaks existing peers without a protocol migration;
- pushes mesh/config policy upstream;
- adds UDP to Eggtunnel without negotiated/bounded semantics;
- declares convergence successful when the old implementation remains active;
- creates a new standalone SynVoid tunnel repo.
