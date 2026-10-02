# Phase 118 Plan: Mesh Application-Dispatch Capability Inversion

Status: **CLOSED DEFER** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

Predecessor: Phase 110 CLOSED RETAIN INTERNAL. This phase reopens only the
application-dispatch seam under the new monorepo-first goal; it does not authorize
consensus/DHT extraction or external publication.

## Goal

Make `synvoid-mesh` stop knowing concrete SynVoid application services where
messages are transported/received. The mesh crate should own peer identity,
transport, protocol handling, liveness and distributed-state mechanisms; the
application composition layer should own dispatch into proxy/cache/tunnel/
serverless/DNS/threat-policy implementations.

Phase 119 may consider a reusable mesh-runtime crate only after this inversion is
proven.

## Research constraints

Existing ecosystem components already cover generic networking:

- rust-libp2p: Kademlia, Identify, Gossipsub and transport composition;
- Iroh/noq: authenticated/public-key endpoint connectivity, relays, hole punching,
  QUIC streams/datagrams;
- OpenRaft: consensus engine.

This phase must not create a second generalized networking stack merely to avoid
dependencies. It isolates SynVoid's existing runtime first. Any proposed adoption
of libp2p/Iroh/noq or OpenRaft upgrade is a separately measured plan.

## Workstream A — map concrete application reachability

Reproduce and expand Phase 110's map of every production source reference from
`synvoid-mesh` to:

- `synvoid-config`;
- `synvoid-proxy`;
- `synvoid-proxy-cache`;
- `synvoid-tunnel`;
- `synvoid-serverless`;
- DNS/application control types;
- root-specific policy or persistence types.

For each edge classify:

- transport/session need;
- distributed-state mechanism need;
- application command/event dispatch;
- configuration translation;
- observability only.

Do not move code until classification is recorded.

## Workstream B — application event/command seam

Introduce narrow mesh-owned event/value types for inbound application-visible
events and application-requested outbound operations.

Prefer typed capabilities such as:

- peer/session event sink;
- service advertisement/lookup interface;
- application message sink;
- canonical-state command interface;
- advisory-record interface.

Do not use an untyped `serde_json::Value` event bus or giant
`MeshApplicationBackend` trait that reproduces every SynVoid service.

The composition root supplies adapters that call proxy/cache/tunnel/serverless/DNS
owners.

## Workstream C — config/identity inversion

Move runtime-only mesh configuration into mesh-owned DTOs where safe, preserving
persisted `synvoid-config` ownership at the application boundary.

Identity/public-key/value semantics needed by transport should be owned by
`synvoid-mesh-protocol` or the mesh runtime, not by application config.

Private/custody policy remains in the correct existing owner; do not push
application secrets into protocol value types.

## Workstream D — preserve authority boundary

Pin tests proving:

- Raft-backed canonical state still requires quorum/commit semantics;
- advisory DHT records cannot mutate canonical enforcement without the existing
  policy/attestation gates;
- partition behavior is unchanged;
- application dispatch failure cannot be mistaken for canonical commit success;
- provenance and freshness survive adapter translation.

This is the highest-priority regression barrier.

## Workstream E — dependency reduction target

The phase should remove concrete application-service dependencies where they exist
solely for dispatch/adapters.

Do NOT force removal of OpenRaft, SQLite, crypto, QUIC or
`synvoid-mesh-protocol`; those are mesh mechanism dependencies.

If a dependency remains, document source references proving it belongs in mesh
mechanism rather than application composition.

## Workstream F — external ecosystem comparison record

Produce an architecture note comparing the post-inversion runtime against
rust-libp2p and Iroh/noq at the level of:

- peer identity/addressing;
- discovery;
- NAT traversal/relay;
- QUIC transport;
- pubsub/gossip;
- DHT;
- liveness;
- application protocol dispatch;
- security/advisory state;
- consensus integration.

The purpose is to prevent Phase 119 from extracting a crate that merely duplicates
an existing library. A later adoption spike must be separately registered and
benchmarked.

## Verification

Minimum:

```bash
cargo test -p synvoid-mesh-protocol --profile ci
cargo test -p synvoid-mesh --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Add focused authority/dispatch differential tests.

## Acceptance criteria

- transport/runtime code no longer directly calls concrete proxy/cache/tunnel/
  serverless implementations where an application adapter suffices;
- config translation occurs at a clear application boundary;
- canonical/advisory authority semantics are unchanged and tested;
- before/after dependency reachability is recorded;
- Phase 119 has a precise candidate seam, or an evidence-backed RETAIN decision.

## Rejection criteria

Reject implementation that:

- creates `synvoid-mesh-consensus` or `synvoid-mesh-dht` merely from directory
  names;
- changes wire format while moving dispatch;
- creates a generic event bus with weaker typing/provenance;
- makes DHT advisory state canonical;
- replaces transport with libp2p/Iroh/noq without a separate parity/performance
  plan;
- upgrades OpenRaft as incidental extraction work.

## Formal closeout

Disposition: **DEFER**. The source map confirmed direct runtime coupling in
`mesh/proxy.rs` (owns `ProxyCache`, cache settings and response mutation),
`transport_peer.rs` (invokes `ServerlessManager` and constructs HTTP responses),
`transport.rs` (stores the concrete serverless manager and tunnel QUIC types),
and `backend.rs` (translates concrete cache configuration). Those are active
dispatch and state-ownership paths, not dead manifest edges. A safe inversion
requires typed async request/response capabilities plus composition-root wiring
and differential authority, failure, cancellation, and protocol tests. This pass
did not produce that seam or its parity proof; retaining the concrete paths is
safer than introducing an incomplete adapter or changing wire behavior.

The full dependency reduction and runtime behavior gates remain outstanding.
Phase 119 is **BLOCKED ON PHASE 118**. Phases 120, 121 and 122 remain independent
and eligible. See `architecture/standalone_crate_phase118_closeout.md`.
