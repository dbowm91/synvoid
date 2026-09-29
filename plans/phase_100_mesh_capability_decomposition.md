# Phase 100 Plan: Mesh Capability Decomposition and Application Dependency Inversion

Status: implemented and closed 2026-09-29.

Closeout: `architecture/mesh_capability_decomposition_phase100_closeout.md`.

Registered in: plans/roadmap.md and plans/architecture_maintenance_auditability_roadmap.md.

Planning baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2. Execute after Phase 99 and rebase to the current main.

Depends on: Phases 96-99.

## Goal

Reduce the internal and external capability reach of synvoid-mesh without changing mesh protocol behavior, distributed-state authority, consensus semantics, or supported application integrations.

This phase does not split synvoid-mesh into multiple crates by default. It first establishes explicit internal capability seams and consumer-owned adapters. A future consensus extraction is a Phase 101 decision, not a Phase 100 assumption.

## Current-head findings

synvoid-mesh remains a justified subsystem: it has independent DHT, Raft, trust, transport, crypto, lifecycle, distribution, and policy invariants.

The maintenance problem is that MeshTransport and related modules can reach a very broad state set:

- topology/certificates/peer connections;
- QUIC/tunnel runtime;
- DHT/routing/record store;
- pending protocol queries and snapshots;
- org/tier keys and session state;
- threat intelligence and reputation;
- YARA/WASM distribution;
- serverless integration;
- optional DNS state;
- site synchronization;
- canonical/Raft/replica state;
- lifecycle/task ownership and shutdown state.

Several extension modules rely on broad crate-private access or use-super patterns. That makes capability review difficult even when each behavior is correct.

Application crates also opt into the full mesh crate for narrow services, for example upload YARA-rule coordination.

## Binding distributed-state constraints

This phase must preserve architecture/distributed_state_contract.md and mesh trust-domain rules.

Specifically:

- canonical Raft-derived authority remains distinct from advisory DHT state;
- no advisory record becomes canonical because types move;
- freshness/stale policy remains unchanged;
- partition behavior remains unchanged;
- replay/order/provenance semantics remain unchanged;
- blocklist enforcement ownership remains local/policy-gated as currently defined;
- no global singleton is introduced to replace explicit capability injection.

## Workstream A — build an internal capability map

Before changing structs, generate a field/method/module ownership matrix for MeshTransport and MeshTransportManager.

For every field or service identify:

- owning domain: transport, consensus, DHT/data, identity/security, application bridge, lifecycle;
- writers and readers;
- whether access is hot-path or control-plane;
- whether it crosses task boundaries;
- whether it is required under minimal mesh configuration;
- whether a narrow trait already exists.

Use the matrix to define a small number of cohesive internal capability aggregates. Example categories are illustrative, not binding names:

- PeerTransportState
- DistributedDataServices
- ConsensusServices
- SecurityIdentityState
- ApplicationBridgeServices
- MeshLifecycleState/Task ownership

Avoid one struct per field. The goal is auditable authority clusters.

## Workstream B — stop extension modules from having ambient access to the full transport

Replace broad friend-style access with explicit method receivers or capability references.

A module that only handles peer authentication should not be able to mutate Raft state, serverless registries, YARA distribution, and lifecycle state through the same object.

Prefer:

- private fields on aggregates;
- narrow getters/operations;
- capability-specific Arc references passed to async tasks;
- explicit constructor wiring.

Do not introduce a service-locator map, Any-based global bag, or dynamic string lookup as a replacement.

## Workstream C — separate protocol transport from application bridges

Audit mesh HTTP proxy, serverless, upload/YARA, honeypot/intel, DNS, and site-sync integration.

Where mesh core only needs an application capability, define a narrow contract and implement it at root composition with an adapter type.

Important Rust ownership rule: if both trait and concrete service type are foreign to root, create a root-owned adapter struct rather than introducing a reverse dependency solely to satisfy orphan rules.

High-value targets:

### Upload/YARA

synvoid-upload should not require full synvoid-mesh merely to obtain approved/distributed YARA rules.

Define a consumer-owned rule-snapshot/provider contract in the narrow upload/YARA policy layer. Root composition wraps the mesh YaraRulesManager in an adapter.

Preserve all current signed-rule, version, digest, approval, fallback, and failure-policy semantics.

### Honeypot/threat-intel publication

If synvoid-honeypot only requires a narrow publication/observation service, inject that capability rather than the full mesh runtime.

Do not change what honeypot evidence is trusted/actionable.

### Mesh HTTP proxy bridge

The mesh proxy path currently reaches into synvoid-proxy for header sanitization/private-address behavior and proxy-cache types.

First use the canonical synvoid-core restricted-address helper for IP classification.

Then separate mesh wire/protocol handling from local reverse-proxy/cache implementation where practical:

- mesh core owns peer message validation/framing/routing;
- application/proxy adapter owns local HTTP proxy/cache execution;
- shared hop-by-hop/header semantics have one canonical owner.

Do not duplicate the RFC hop-by-hop list to remove a dependency. If the clean adapter cannot be completed without a new broader coupling, document the residual and keep the edge until a focused follow-up.

## Workstream D — make canonical/consensus seams independent of transport implementation

The existing CanonicalTrustReader and ConsensusTransport style seams are valuable.

Strengthen them so:

- canonical read policy can be tested without constructing full MeshTransport;
- Raft network/state-machine tests can use minimal transport adapters;
- transport message handling cannot directly mutate canonical state outside the documented consensus path;
- edge replica freshness and canonical snapshots retain current semantics.

Do not extract a new crate in this workstream.

The objective is to determine whether a future synvoid-mesh-consensus crate would have a one-way, low-capability dependency boundary after Phase 100.

## Workstream E — reduce feature-coupled application dependencies

Recompute which workspace crates import synvoid-mesh and why.

For every non-root reverse dependency classify it as:

- needs protocol/wire vocabulary only -> prefer synvoid-mesh-protocol;
- needs a narrow runtime service -> inject a capability adapter;
- legitimately is part of mesh implementation -> retain full dependency.

Do not remove a full mesh edge if doing so duplicates consensus/security logic in the consumer.

## Workstream F — lifecycle and task ownership preservation

Capability decomposition must not orphan async tasks.

Every task must retain:

- one lifecycle owner;
- explicit shutdown signal;
- bounded drain/join behavior;
- generation identity where currently used;
- startup rollback behavior;
- existing required-vs-optional mesh startup semantics.

Add static/behavioral guards if moving fields makes it possible to spawn unregistered tasks.

## Workstream G — performance and allocation discipline

Mesh is a latency-sensitive/network-heavy subsystem. Avoid replacing direct typed access with repeated locking/dynamic dispatch on hot paths merely for architectural aesthetics.

Measure before/after for representative:

- peer message dispatch;
- DHT lookup;
- route query;
- canonical read;
- proxy message handling;
- connection/session lookup.

A small trait dispatch cost can be accepted for control-plane/application bridges if it materially reduces capability coupling. Do not accept a material unexplained hot-path regression.

## Required verification

At minimum:

    cargo test -p synvoid-mesh --profile ci --features mesh
    cargo test -p synvoid-upload --profile ci --features mesh
    cargo test -p synvoid-honeypot --profile ci --features mesh
    cargo test --test boundary_composition_guard --profile ci
    cargo test --test mesh_id_boundary_guard --profile ci
    cargo check --no-default-features --features mesh --profile ci
    cargo check --no-default-features --features mesh,dns --profile ci
    cargo xtask test guards
    cargo xtask verify

Run the existing mesh lifecycle, distributed-state, canonical-freshness, replay/convergence, and failure-injection suites.

Record focused benchmark deltas for touched hot paths.

## Acceptance criteria

- MeshTransport no longer acts as an ambient capability bag for unrelated extension modules.
- Internal capability groups have explicit ownership and narrower access.
- At least the highest-value application integrations use narrow adapters where doing so reduces full-mesh dependency reach without duplicating logic.
- Upload/honeypot/proxy integration behavior remains equivalent.
- Canonical vs advisory authority is unchanged.
- Raft/DHT/replica/freshness/partition semantics are unchanged.
- Task lifecycle/startup rollback semantics remain intact.
- No material unexplained performance regression is introduced.
- A measured Phase 101 extraction-readiness assessment can now evaluate consensus as a genuine one-way boundary.

## Rejection criteria

Reject the phase if it:

- creates multiple new mesh crates solely because synvoid-mesh is large;
- replaces explicit typed state with a generic service locator;
- duplicates proxy/header/security policy;
- changes canonical/advisory authority;
- moves application code into mesh to avoid adapters;
- weakens signed YARA/WASM/threat-intel policy;
- loses task ownership or shutdown accounting;
- introduces new globals to make wiring easier;
- accepts significant lock/dynamic-dispatch overhead on hot paths without evidence.
