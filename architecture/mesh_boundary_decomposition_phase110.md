# Phase 110: Mesh Boundary Decomposition

Status: **CLOSED — RETAIN INTERNAL; no crate extraction qualified**.

## Decision

Keep canonical consensus, advisory DHT/storage, transport, and application
adapters inside `synvoid-mesh`. The plan's source and dependency audit did not
identify a proven one-way seam whose extraction reduces capabilities or
application-service reach. Creating `synvoid-mesh-consensus` or
`synvoid-mesh-dht` now would mirror existing module directories while retaining
shared configuration, identity, transport, and policy coupling.

This is an extraction decision, not a claim that the mesh boundary is
application-neutral. The direct `synvoid-config`, `synvoid-tunnel`,
`synvoid-proxy`, `synvoid-proxy-cache`, and `synvoid-serverless` dependencies
remain in the crate. Their uses are concrete adapters: config conversion in
`mesh/config.rs`, `protocol.rs`, and `transports/manager.rs`; QUIC and incoming
connection integration in `transport.rs`; service dispatch in transport peer
handlers; and proxy/cache work in `mesh/proxy.rs` and `mesh/backend.rs`. They
are not evidence of an independent consensus/DHT library boundary.

## Ownership map

| Area | Canonical owner and dependencies | Authority / disposition |
|---|---|---|
| Consensus commands, membership, log and SQLite snapshots | `mesh/raft/{instance,client,network,state_machine,edge_replica}.rs`; openraft, rusqlite, postcard, mesh transport | Canonical committed state. Keep together: deterministic state application and persistence are coupled; network adapter is mesh-message-specific. |
| Canonical trust composition | `mesh/canonical.rs`; Raft client/replicas, policy snapshots, config freshness | Canonical reads/writes and freshness outcomes. Keep as mesh composition; must not fall back to advisory DHT. |
| DHT keys, ingress authority, signatures, TTL, replay, storage, sync and routing | `mesh/dht/**`; mesh protocol values, identity/crypto, local stores, optional canonical reader, transport | Advisory by default; canonical-class records require attestation/quorum proof. Keep the typed policy and storage path together until neutral identity/config/transport contracts exist. |
| Wire and verification vocabulary | `synvoid-mesh-protocol` | Low-capability value and verification crate. No promotion or protocol duplication. Compatibility guidance updated in crate rustdoc. |
| Transport and dispatch | `mesh/transport*.rs`, `mesh/transports/**`, `mesh/backend.rs`, `mesh/proxy.rs` | Moves messages and peer identity, but also currently owns lifecycle and application dispatch. This is the main future decomposition seam; extracting consensus/DHT before narrowing it would invert or preserve broad edges. |
| Persistence | Raft SQLite state machine; DHT record-store memory/disk/sync modules | Distinct persistence models and authority; do not combine behind untyped storage. |

## Dependency evidence

The five direct service edges named in the plan remain referenced by source.
The source references listed above are live, not manifest-only edges. No edge or
source LOC was removed in this phase. The Phase 23 contract
`architecture/distributed_state_contract.md` remains binding: DHT says what was
advertised; Raft/canonical state says what is trusted; policy says what may be
acted on. No authority, wire, replay, freshness, or partition behavior changed.

## Protocol documentation

`synvoid-mesh-protocol/src/lib.rs` now states that Rust semver and wire
compatibility are distinct, describes replay clock/persistence assumptions, and
requires explicit compatibility decisions, golden vectors, and mixed-version
coverage for wire evolution. No wire representation changed.

## Follow-up gate

Reconsider extraction only after transport/application dispatch is behind narrow
consensus, DHT, application-router, and lifecycle capabilities, and neutral config
and identity contracts exist. Then recompute package dependency closure and prove
that an extracted crate cannot reach proxy/cache/serverless/tunnel/config while
preserving the partition and replay test matrix. Phase 111 remains independently
eligible; this decision does not block tunnel convergence.
