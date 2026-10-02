# Phase 119 Plan: Mesh Runtime Extraction Decision and Standalone Qualification

Status: **BLOCKED ON PHASE 118** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

## Goal

After application-dispatch inversion, determine whether a genuine reusable
peer/network runtime exists inside `synvoid-mesh`. If and only if a one-way seam
is proven, extract it as an internal workspace crate (working name
`synvoid-mesh-runtime`) and qualify it as standalone-capable class 2.

A RETAIN result is acceptable and preferable to a wrapper crate with the same
dependency graph.

## Workstream A — extraction gate

Before creating a crate, prove that the candidate can own a coherent set such as:

- peer/session lifecycle;
- authenticated transport;
- framing/protocol dispatch using `synvoid-mesh-protocol`;
- liveness/heartbeat;
- connection management;
- routing/discovery primitives that are not application policy;
- bounded event delivery to embedding applications.

The candidate must NOT own:

- SynVoid proxy/cache/serverless/tunnel implementations;
- SynVoid persisted config;
- WAF/threat enforcement policy;
- DNS application policy;
- root Supervisor/worker types.

Consensus/DHT stay in `synvoid-mesh` unless a separate one-way dependency proof
shows they naturally belong below the runtime. Phase 110's RETAIN decision remains
the default for them.

## Workstream B — compare three shapes

Evaluate with actual dependency graphs:

1. **RETAIN**: `synvoid-mesh` remains one domain crate after Phase 118.
2. **runtime leaf**: create `synvoid-mesh-runtime`; `synvoid-mesh` depends on it.
3. **protocol + runtime composition**: runtime depends only on
   `synvoid-mesh-protocol` plus third-party networking/crypto/runtime crates;
   consensus/application state remains above.

Choose based on dependency reachability and API coherence, not LOC.

## Workstream C — avoid ecosystem duplication

Use the Phase 118 comparison record.

If the candidate's primary value is already supplied cleanly by rust-libp2p or
Iroh/noq, stop and register a later adoption/parity spike instead of creating a
new general-purpose crate.

If SynVoid's needed semantics are materially different (for example explicit
peer/session contract and application-neutral event delivery without adopting a
full libp2p stack), document that scope narrowly.

## Workstream D — package API

If GO_EXTRACT:

- depend on `synvoid-mesh-protocol` through a version+path edge;
- expose no SynVoid application types;
- make transport/resource ceilings explicit;
- make shutdown/drain ownership explicit;
- surface typed identity/auth/replay errors;
- classify wire API separately from Rust API;
- avoid global registries where an owned runtime handle can be used;
- make observability optional/facade-based where practical.

## Workstream E — standalone consumer

Package the candidate and run an outside-workspace consumer that:

- creates at least two local peers;
- performs authenticated connection/session establishment;
- exchanges a bounded application-neutral message/event;
- exercises liveness and clean drain;
- rejects malformed/oversized/replayed input according to current contracts;
- does not require SynVoid config files, global process state or application
  crates.

If the candidate cannot provide a useful consumer without importing
`synvoid-mesh`, mark RETAIN.

## Workstream F — performance/security evidence

Record:

- handshake/session latency;
- steady-state message throughput/allocations where existing benches permit;
- dependency/package size;
- malformed-frame and connection-churn behavior.

Do not claim improvement unless measured. Recent libp2p-quic panic history makes
panic-free hostile-peer tests particularly important for any reusable network
runtime.

## Verification

If GO_EXTRACT:

```bash
cargo test -p synvoid-mesh-protocol --profile ci
cargo test -p synvoid-mesh-runtime --profile ci
cargo test -p synvoid-mesh --profile ci
cargo package -p synvoid-mesh-runtime --allow-dirty
cargo publish -p synvoid-mesh-runtime --dry-run
cargo xtask <standalone-consumer-command> synvoid-mesh-runtime
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify-full
cargo deny check
cargo audit
```

No actual publish.

## Acceptance criteria

Exactly one terminal decision is recorded:

- **GO INTERNAL EXTRACT** — real one-way runtime boundary, standalone consumer
  passes, dependency reachability is reduced; or
- **RETAIN** — evidence shows the runtime is still inseparable or would merely
  duplicate ecosystem libraries.

Neither outcome authorizes repository extraction or class-3 promotion.

## Rejection criteria

Reject implementation that:

- creates a crate before the gate;
- moves consensus/DHT solely to lower LOC;
- makes the new crate depend on application services;
- hides wire changes in refactoring;
- adopts a networking framework without parity/security/performance evidence;
- treats outside-workspace compile-only proof as sufficient runtime qualification.
