# Phase 27 Plan: Mesh Protocol and Identity Contract Extraction

Status: ready for implementation after Phase 25; may proceed in parallel with Phase 26.

Roadmap position: Track 4, Phase 27.

Primary goal: let consumers use stable mesh wire/identity/signature vocabulary without linking the full `synvoid-mesh` control-plane dependency graph.

## Context

`synvoid-mesh` is intentionally large because it owns DHT, transport, Raft, trust, replicated-state policy, persistence, certificate handling, YARA distribution, HTTP/gRPC surfaces, and other control-plane behavior. Its size alone is not a reason to split it.

The useful extraction boundary is narrower. `crates/synvoid-mesh/src/mesh/protocol.rs` and nearby protocol types contain `MeshMessage`, message serialization/compression, `MeshMessageSigner`, replay/version constants and identity/signature vocabulary. Selected consumers need those contracts or verification primitives but should not gain DHT/Raft/SQLite/YARA/HTTP authority merely by depending on `synvoid-mesh`.

The current protocol file is not yet low-level: `MeshMessageSigner` reaches `CryptoVerificationPool`, hybrid/PQ signature types, ML-DSA signer/verifier, organization tier claims, mesh config roles, and transport types. Extraction therefore requires separating stable wire vocabulary from implementation services rather than moving the file verbatim.

## Target architecture

Create a low-capability crate, tentatively `crates/synvoid-mesh-protocol/`, with a strict dependency budget.

Allowed dependency classes should be limited to what is necessary for stable wire/identity semantics, for example:

- `serde` / `postcard` / `prost` or the single chosen wire serializer;
- `bytes` if needed by framing;
- `ed25519-dalek`, `subtle`, `sha2`/digest only when verification is part of the contract;
- `synvoid-utils` only if a truly low-level type such as `ArcStr` is required;
- PQ/hybrid signature value types only if they can be represented without pulling runtime pools/configuration.

The protocol crate must not depend on:

- `synvoid-mesh`;
- OpenRaft;
- rusqlite;
- QUIC/Hyper/Axum/Tonic server runtime beyond generated message types if unavoidable;
- YARA;
- proxy/tunnel/serverless implementations;
- mesh persistence or policy managers;
- root `synvoid`.

## Part A — Inventory and classify protocol types

Inventory `protocol.rs`, `protocol_types.rs`, generated proto definitions, message enums, signing helpers, transport identifiers, organization/tier claims, attestation/value types, and their reverse dependencies.

Classify each item as:

1. **wire contract** — serialized and exchanged between peers;
2. **identity/verification primitive** — stable key/signature verification with no runtime service ownership;
3. **runtime service** — verification pools, key managers, async offload, config access;
4. **control-plane policy** — role/tier/authority decisions;
5. **transport implementation** — connection/QUIC/TCP concerns.

Only classes 1-2 belong in the new crate. Represent classes 3-5 through adapters or stable IDs/enums where required by the wire format.

## Part B — Separate signer value semantics from runtime acceleration

`MeshMessageSigner` currently mixes key ownership, Ed25519 signing, hybrid/PQ signing, and an optional `CryptoVerificationPool`.

Refactor toward:

- low-level key/signature value types and synchronous deterministic verification in `synvoid-mesh-protocol`;
- runtime/offload pools in `synvoid-mesh` implementing an interface over those value types;
- PQ signer implementation remaining in the lowest crate that can own it without dragging control-plane services downward.

If PQ implementation cannot be extracted cleanly because it depends on `pqc`/aws-lc runtime details, keep the signer service in `synvoid-mesh` and move only canonical signature envelopes plus Ed25519 verification into the protocol crate. Do not force PQ code downward merely to preserve the current `MeshMessageSigner` name.

## Part C — Stabilize generated protobuf ownership

The root build script and mesh crate currently both generate protobuf code into separate `OUT_DIR`s. During this phase determine whether shared wire protobufs belong in `synvoid-mesh-protocol`.

Preferred end state:

- one canonical build owner for peer wire DTOs;
- root no longer compiles `src/mesh/proto/mesh.proto` solely for compatibility if no live root consumer remains;
- control/admin protobufs that are not mesh peer wire contracts remain in their appropriate package.

Do not introduce a `-sys` crate solely to eliminate duplicate codegen unless it actually simplifies dependency direction and publishing.

## Part D — Migrate consumers deliberately

Migrate only consumers that need protocol/identity contracts and not full mesh behavior.

Candidate consumers include:

- signature verification in root WAF feed code currently allowlisted for `MeshMessageSigner`;
- crates that carry mesh IDs, signed envelopes, block/threat event DTOs, or attestations without executing DHT/Raft behavior;
- test/fuzz harnesses for wire decoding.

Keep actual mesh managers/transports/consensus code dependent on `synvoid-mesh-protocol`, not the reverse.

Add a temporary compatibility re-export from `synvoid-mesh` if stability policy requires `synvoid_mesh::protocol::*` to remain valid.

## Part E — Guard the dependency boundary

Add repo guards that fail if `synvoid-mesh-protocol` adds prohibited dependency families or imports control-plane crates.

Also add a consumer guard: any non-mesh crate that imports full `synvoid-mesh` only for protocol/identity types should be migrated or explicitly justified.

The protocol crate should be buildable/testable with no mesh feature and no network access.

## Part F — Serialization compatibility

Because this is a wire-contract move, preserve byte compatibility.

Required evidence:

- golden vectors for representative `MeshMessage` variants;
- version/replay fields preserved;
- signature canonicalization preserved;
- old `synvoid-mesh` encode/decode vs new protocol crate differential tests during migration;
- malformed input remains bounded/fail-closed;
- no implicit serde representation changes for enums/structs;
- protobuf package/message numbers unchanged unless an explicit protocol version bump is planned.

If any type cannot move without changing serialized representation, leave it in `synvoid-mesh` for this phase rather than silently changing the protocol.

## Part G — Dependency impact report

After migration record:

```bash
cargo tree -p synvoid-mesh-protocol
cargo tree -p synvoid-mesh
cargo tree -i synvoid-mesh --workspace
cargo tree -i synvoid-mesh-protocol --workspace
```

The success metric is not LOC. It is that selected consumers lose dependencies such as OpenRaft/SQLite/YARA/transport stacks while retaining only the wire/verification contracts they actually need.

## Tests

Add:

- golden wire vectors;
- encode/decode round trips and malformed bounds;
- signature verification vectors;
- replay/version constant tests;
- differential old/new serialization during migration;
- feature-minimal package compile test;
- dependency-boundary guard;
- existing mesh partition/distributed-state suites to prove no authority semantic changes.

## Documentation updates

Update:

- `architecture/mesh.md`;
- `architecture/mesh_trust_domains.md`;
- `architecture/distributed_state_contract.md` only for type ownership links, not semantics;
- `architecture/crate_granularity_audit.md`;
- root/request-path capability guards where the full-mesh import is replaced by protocol-only verification;
- `AGENTS.md` stale path map and composition boundary notes.

## Acceptance criteria

Phase 27 is complete when:

- a low-capability mesh protocol/identity crate exists with an explicit dependency budget;
- stable wire serialization/signature behavior is byte-compatible or intentionally versioned;
- runtime verification pools, Raft, DHT, persistence, YARA, and transport implementations remain outside it;
- selected cross-boundary consumers no longer depend on full `synvoid-mesh` merely for protocol/signature types;
- `synvoid-mesh` depends downward on the protocol crate and may re-export compatibility paths if required;
- distributed-state authority and partition semantics are unchanged;
- dependency-tree evidence demonstrates real transitive capability reduction.

## Rejection criteria

Reject an implementation that:

- copies `protocol.rs` wholesale and thereby drags control-plane services into the new crate;
- moves policy authority or Raft state types downward just to make imports convenient;
- breaks wire compatibility without an explicit protocol-version migration;
- creates circular dependencies or requires the protocol crate to import `synvoid-mesh`;
- claims success based on LOC rather than reduced consumer dependencies.

## Verification

```bash
cargo test -p synvoid-mesh-protocol --all-targets
cargo test -p synvoid-mesh --all-targets --features mesh
cargo test --test mesh_id_boundary_guard --features mesh
cargo test --test boundary_composition_guard --features mesh
cargo test -p synvoid-repo-guards
cargo xtask verify
cargo tree -p synvoid-mesh-protocol
cargo tree -i synvoid-mesh --workspace
```