# Phase 110 Plan: Mesh Consensus and DHT Boundary Decomposition

Status: **PLANNED**.

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline for registration: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).

Owner: mesh / distributed systems / architecture.

Predecessors: Phase 100 internal mesh capability decomposition and Phase 101
RETAIN decision for consensus extraction.

## Goal

Create demonstrably one-way internal boundaries for canonical consensus/state
machine logic and advisory DHT/storage logic without moving the aggregate mesh
subsystem to another repository.

This phase is deliberately narrower than "split mesh." It should extract only
mechanisms with independent invariants and measurable audit/dependency benefit.

## Current state

`synvoid-mesh` still directly depends on application/service crates including:

- `synvoid-config`;
- `synvoid-tunnel`;
- `synvoid-proxy`;
- `synvoid-proxy-cache`;
- `synvoid-serverless`.

It also owns Raft, DHT, transport, cryptographic identity, organizations,
reputation, threat intelligence, distributed YARA/WASM state, proxying, DNS
integration, and worker lifecycle.

Phase 101 correctly rejected immediate `synvoid-mesh-consensus` extraction
because the application-service-free boundary had not been demonstrated.

## Binding distributed-state invariant

This phase may not change the authority contract:

- canonical security/control state uses the canonical/Raft authority path;
- DHT/peer-distributed state is advisory unless a specific namespace contract
  says otherwise;
- stale/partitioned/advisory records cannot silently become canonical writes;
- provenance, replay, freshness and partition semantics remain unchanged.

Crate layout is subordinate to that invariant.

## Workstream A — produce a dependency-level state ownership map

Inventory every type/function in:

- `mesh/raft/**`;
- `mesh/canonical/**`;
- `mesh/dht/**`;
- persistence/snapshot code;
- protocol/value types consumed by these modules;
- transport interfaces used by consensus/DHT;
- application callbacks reached from state application.

For each identify:

- protocol/value dependency;
- crypto/identity dependency;
- persistence dependency;
- transport/network dependency;
- application-service dependency;
- metrics/config dependency;
- canonical or advisory authority role.

Do not start by creating crates.

## Workstream B — define a canonical state-machine seam

A candidate consensus boundary should own only concepts necessary to replicate
canonical state:

- canonical commands/events;
- deterministic state-machine application;
- log/snapshot state;
- membership where it is part of consensus;
- persistence contracts;
- canonical read/write outcomes/freshness semantics.

OpenRaft transport/storage integration should enter through narrow adapters.

The candidate must not depend on:

- proxy;
- proxy cache;
- serverless;
- tunnel;
- DNS;
- WAF/admin/root config;
- application lifecycle.

Application services translate their domain requests into canonical commands at
the composition/control-plane layer.

If deterministic state application currently invokes application services,
first separate command application from side-effect projection.

## Workstream C — define an advisory DHT/storage seam

A candidate DHT boundary should own:

- signed record keys/values;
- record store and TTL/freshness;
- Merkle/synchronization mechanics;
- replay/provenance/access-control invariants that are generic to records;
- persistence abstraction;
- routing/storage protocol needed for DHT operation.

It must not directly own YARA, WASM, DNS, threat-intel or proxy domain objects.
Those consumers map their data into neutral typed records or namespace adapters.

Avoid erasing important types into arbitrary JSON blobs. Generic does not mean
untyped.

## Workstream D — separate transport from application dispatch

Consensus/DHT network traits should move bytes/messages and peer identity, not
dispatch proxy/serverless/DNS/tunnel work.

Where `MeshTransport` still exposes broad state, replace direct field/friend
access with narrow handles:

- consensus network;
- DHT network;
- application message router;
- lifecycle/shutdown capability.

Keep `synvoid-mesh-protocol` the low-capability wire/identity vocabulary and
avoid duplicating protocol enums into new crates.

## Workstream E — config and observability

Candidate low-level state crates should consume neutral config/value structs
rather than `synvoid-config`.

Observability should use lightweight tracing/metrics facades or injected event
sinks only where necessary. Do not pull root/admin configuration into state
mechanisms for logging convenience.

## Workstream F — decide crate boundaries only after graph proof

Possible outcomes:

1. create `synvoid-mesh-consensus` if the canonical seam is one-way and reduces
   capability reach;
2. create `synvoid-mesh-dht` if the advisory seam independently meets the same
   bar;
3. extract only one;
4. retain both as internal modules if new crates would merely mirror directories.

A split is justified only if cargo metadata shows fewer application/unsafe/large
dependency edges for the extracted unit.

No external repository/publication is authorized.

## Workstream G — compatibility and failure testing

Add/retain tests for:

- deterministic command application;
- snapshot/log recovery;
- leader/follower/re-election behavior;
- partition and stale-read semantics;
- DHT TTL/freshness/replay;
- Merkle reconciliation;
- malformed/forged record rejection;
- canonical-vs-advisory namespace enforcement;
- shutdown/restart;
- transport failure injection.

Wire bytes remain compatible unless separately versioned.

## Workstream H — mesh-protocol publication hygiene, no promotion

While touching the bottom layer, close cheap documentation gaps in
`synvoid-mesh-protocol`:

- explicit wire compatibility vs Rust semver;
- replay/time assumptions;
- enum/message evolution policy;
- remove phase-history wording from consumer rustdoc where appropriate.

Do not promote it to class 3/public support in this phase.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-mesh --profile ci
cargo test -p synvoid-mesh-protocol --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Recompute cargo metadata/tree before and after any crate extraction.

## Acceptance criteria

- canonical and advisory state ownership is more explicit;
- any new consensus/DHT crate has no application-service dependency;
- application side effects are projected outside deterministic state application;
- broad `MeshTransport` friend-style state access is reduced;
- distributed authority semantics are unchanged and tested;
- dependency graph shows measurable audit/capability reduction;
- aggregate mesh remains in SynVoid.

## Rejection criteria

Reject implementation that:

- creates `mesh-core`/microcrates merely to reduce LOC;
- moves application service integrations into a supposedly low-level state crate;
- turns records into untyped JSON to avoid dependencies;
- duplicates `synvoid-mesh-protocol`;
- changes Raft/DHT authority or partition semantics;
- starts an external mesh repository;
- claims improvement without graph evidence.
