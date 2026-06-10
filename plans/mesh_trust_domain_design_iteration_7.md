# Mesh Trust-Domain Design — Iteration 7

## Goal

Start the next architecture track with a design-first pass for `synvoid-mesh`. Do not move large amounts of code yet. The goal is to define the trust-domain boundaries that the mesh implementation must preserve before doing an internal module split.

The key invariant is:

> DHT answers "what has been advertised?" Raft/canonical state answers "what is trusted?" Policy answers "what may be acted on?" Transport answers "how do peers communicate?" Services consume policy outputs, not raw advisory records, when security decisions are involved.

This iteration should produce a concrete design note and a small set of low-risk boundary interfaces or markers only if they clarify the design without requiring broad code movement.

## Non-Goals

Do not split `synvoid-mesh` into multiple crates in this pass.

Do not rewrite DHT, Raft, peer discovery, identity, transport, threat-intel, YARA, WASM, or reputation behavior.

Do not change network behavior, record propagation behavior, trust decisions, node roles, certificate handling, or Raft membership behavior.

Do not remove the DHT record-store compatibility global yet.

Do not make feature defaults stricter.

Do not attempt to fully reorganize `crates/synvoid-mesh/src/mesh/` in this pass.

Do not perform unrelated cleanup outside mesh trust-domain design.

## Phase 1 — Inventory Current Mesh Responsibilities

### Required Searches

Run targeted inventory commands:

```bash
find crates/synvoid-mesh/src -maxdepth 4 -type f | sort
rg "Raft|openraft|DHT|Kademlia|RecordStore|ThreatIntel|ThreatIntelligence|Yara|Wasm|reputation|revocation|OrgPublicKey|GlobalNode|certificate|identity|transport|peer|policy|trust|attestation|signature" crates/synvoid-mesh/src architecture docs
rg "get_global_record_store|set_global_record_store|RECORD_STORE_GLOBAL|get_record_store" crates/synvoid-mesh src crates
```

Classify existing files/modules into these conceptual domains:

1. `transport`: peer connections, QUIC transport, wire protocol, retry/reachability, transport manager.
2. `advisory_dht`: DHT/Kademlia storage, TTL-bound records, DHT record validation, discovery records, eventually consistent announcements.
3. `canonical`: Raft/global-node authority records, organization public keys, revocation, global node CA/trust state, canonical threat-intel attestations.
4. `identity`: node identity, certificates, signing, peer auth, key exchange, org identity, crypto material lifecycle.
5. `policy`: trust decisions, record acceptance/activation decisions, canonical-vs-advisory resolution, authorization gates.
6. `services`: YARA/WASM distribution, threat intelligence consumers, reputation, proxy/service discovery, serverless mesh wiring, audit/event consumers.
7. `compat`: legacy globals, transitional shims, APIs kept for root/backward compatibility.

### Deliverable

Create:

```text
architecture/mesh_trust_domains.md
```

or, if architecture docs are organized differently, choose the closest equivalent. The document must include a table mapping current modules/files to the conceptual domains above.

### Acceptance Criteria

Every major mesh file/module is classified.

The classification distinguishes advisory DHT state from canonical trust state.

Compatibility globals are explicitly marked as transitional, not part of the desired core design.

## Phase 2 — Define Trust Invariants

### Required Content

In `architecture/mesh_trust_domains.md`, write explicit invariants. At minimum:

### Advisory DHT Invariants

- DHT records are advisory unless backed by canonical attestation.
- DHT records are TTL-bound or freshness-bound.
- DHT records may aid discovery, routing hints, cache warmup, and distribution, but must not decide authority.
- A DHT record must not silently grant trust, ownership, global-node status, organization authority, or revocation status.
- DHT data may be stale, missing, duplicated, or maliciously advertised.

### Canonical/Raft Invariants

- Canonical trust state comes from Raft/global-node consensus or cryptographically verifiable canonical attestations derived from that state.
- Organization public keys, global-node membership, revocation lists, trusted CA state, and canonical threat-intel attestations belong to the canonical domain.
- Canonical state may be cached locally, but cache consumers must know whether they are reading a snapshot, a stale snapshot, or a live consensus result.

### Identity Invariants

- Node identity and organization identity are separate concepts.
- Peer authentication proves who is speaking; policy decides what the peer is allowed to influence.
- Signing/verifying records should be separate from deciding whether records are actionable.

### Policy Invariants

- Security-sensitive consumers must depend on policy outputs, not raw DHT records.
- Policy is the only layer allowed to combine advisory DHT data with canonical state to produce an actionable decision.
- If canonical state is unavailable, policy must explicitly choose fail-open, fail-closed, or degraded behavior by decision type.

### Service Invariants

- Service modules may consume discovery/advisory records for non-security-critical hints.
- Service modules must not treat advisory records as trust decisions.
- Threat intel/YARA/WASM distribution must distinguish untrusted advertisement, signed package metadata, and canonical approval.

### Acceptance Criteria

The document makes it possible to review future mesh code by checking which invariant it crosses.

The language is normative: use `must`, `must not`, `may`, and `should` deliberately.

## Phase 3 — Define Import Direction and Internal Module Target Shape

### Required Content

In the same design note, define the target internal module shape before code movement.

Suggested target:

```text
crates/synvoid-mesh/src/
  lib.rs
  mesh/
    mod.rs              # public facade and compatibility exports only
    transport/          # transport manager, protocol, wire IO
    advisory_dht/       # DHT records, TTL store, discovery announcements
    canonical/          # Raft/global-node authority interfaces and attestations
    identity/           # node/org identity, cert/key/signature verification
    policy/             # trust resolution and actionable decisions
    services/           # YARA/WASM/threat-intel/reputation/proxy consumers
    compat/             # transitional globals/shims if needed
```

Define allowed import direction. Suggested rule:

```text
transport -> identity only for peer-auth primitives, not policy
advisory_dht -> identity for signature verification primitives only
canonical -> identity for canonical signer/verifier primitives
policy -> advisory_dht + canonical + identity
services -> policy + transport APIs, but not raw advisory_dht internals for security decisions
compat -> may import old paths temporarily, but new code must not import compat
```

Clarify that import direction is a design target. Do not enforce mechanically unless easy.

### Acceptance Criteria

The design note names target modules and allowed dependencies.

It identifies at least three imports or module relationships that should be prevented in future work.

## Phase 4 — Identify First Low-Risk Code Boundary

### Goal

Pick the first actual code boundary for the next implementation pass. This pass may add tiny interfaces or markers only if that helps the design; broad movement comes later.

### Candidate Boundaries

Prefer one of these:

1. `CanonicalTrustReader` / `CanonicalTrustSnapshot`
   - A narrow interface for reading canonical trust state.
   - Consumers ask whether a record/key/node/intel item is canonical/trusted, instead of reading Raft internals directly.

2. `AdvisoryRecordSource`
   - A narrow interface for obtaining DHT-advertised records with freshness/TTL metadata.
   - Does not imply trust.

3. `MeshTrustPolicy`
   - A pure decision layer that takes advisory input and canonical input and returns a typed decision.
   - Good long-term target, but may be too early if inputs are not clear.

4. `RecordTrustLevel`
   - A small enum used in docs/tests to classify record trust:

```rust
pub enum RecordTrustLevel {
    UntrustedAdvertisement,
    SignedByPeer,
    CanonicallyAttested,
    LocallyConfigured,
}
```

Only add code if it is clearly useful and does not force broad rewrites.

### Required Output

In the design note, choose exactly one preferred first implementation boundary and explain why it is lower risk than the alternatives.

### Acceptance Criteria

The next implementation pass can start from a concrete chosen seam.

No broad code movement is required in this design pass.

## Phase 5 — Add Boundary Review Checklist

### Required Content

Add a checklist to `architecture/mesh_trust_domains.md` that reviewers can use for future mesh PRs:

- Does this code consume raw DHT/advisory records?
- If yes, is the use non-security-critical?
- If security-critical, does it pass through policy?
- Does this code treat a signature as authorization?
- Does this code distinguish peer identity from organization/global authority?
- Does this code distinguish canonical state from cached canonical snapshot?
- What is the failure mode when canonical state is unavailable?
- Does this code introduce a new global or compatibility bypass?
- Is TTL/freshness enforced where advisory state is consumed?
- Are service-level consumers prevented from bypassing policy?

### Acceptance Criteria

The checklist is concrete enough to use during code review.

It maps directly back to the invariants.

## Phase 6 — Optional: Lightweight Source Comments Only

### Allowed Changes

If helpful, add short comments to existing modules to mark intended domains. Examples:

```rust
// Domain: advisory_dht. Records here are not authoritative unless policy verifies canonical attestation.
```

```rust
// Domain: compat. Transitional global; new production paths should receive explicit handles.
```

Do not add noisy comments everywhere. Only add comments at high-risk boundaries such as global record store, DHT record validation, Raft/canonical trust exports, and policy-facing consumers.

### Acceptance Criteria

Any code comments added clarify trust-domain intent and do not claim future code movement has already happened.

## Validation Commands

This is mostly a design/doc pass, but still run lightweight checks if code comments or module markers are added:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo check --workspace --all-targets --features mesh
```

If no Rust code changes are made, record that no compile validation was required beyond documentation review.

## Completion Criteria

This iteration is complete when:

- `architecture/mesh_trust_domains.md` exists;
- current mesh files/modules are classified by trust domain;
- advisory DHT, canonical/Raft, identity, policy, transport, services, and compat invariants are documented;
- target internal module shape and import direction are documented;
- exactly one first implementation seam is chosen for the next pass;
- the review checklist exists;
- no broad code movement has occurred.

## Follow-Up Recommendation

The next pass should implement the chosen first seam only. The safest likely first implementation is a narrow canonical/advisory boundary such as `CanonicalTrustReader` plus explicit advisory record types, but defer final selection to the design note produced by this iteration.
