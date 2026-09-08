# Phase 23 Plan: Distributed State Consistency and Partition-Semantics Contract

Status: detailed handoff plan.

Roadmap position: Track 3, Phase 23 of `plans/roadmap.md`.

Primary goal: make the consistency, authority, freshness, expiry, conflict, replay, and partition behavior of every mesh-replicated security datum explicit and mechanically tested, building on the already hardened blocklist convergence and canonical/advisory trust-domain work.

## Context

SynVoid already has substantial distributed-state hardening:

- blocklist convergence uses source-scoped ordering/cursors and stale replay prevention;
- threat-intel ingestion passes through policy gates before mutating enforcement state;
- mesh trust-domain documentation distinguishes advisory data from canonical authority;
- Global-tier records such as organization public keys, canonical threat intelligence, and revocation data are described as Raft-authoritative with DHT material derived from committed state.

The remaining maintenance risk is that these guarantees are documented piecemeal across blocklist, threat-intel, mesh, trust-domain, and admin/control-plane documents. Some documentation also retains older limitation language such as MESH-15 quorum/partition concerns that must be reconciled against the current Raft implementation rather than repeated indefinitely.

This phase does not replace the mesh architecture. It makes each replicated namespace's contract explicit and proves degraded/partition behavior.

## Constraints

- Do not weaken canonical trust to improve availability.
- DHT/advisory state must not become an implicit fallback authority for canonical records during partition.
- Preserve source-scoped blocklist replay/order protections from Phase 5.
- Preserve threat-intel policy gating before enforcement mutation.
- Use monotonic/logical ordering where available; do not rely on wall-clock ordering for security-critical conflict resolution unless the contract explicitly tolerates clock skew.
- Expiry must be deterministic and bounded under clock skew.
- Admin/API responses must distinguish local commit, canonical commit, and best-effort propagation truthfully.
- Do not introduce a second consensus protocol.

## Step 1: Inventory every replicated namespace

Create `architecture/distributed_state_contract.md`.

Inventory every mesh/distributed datum that can affect routing, trust, enforcement, or operator state. At minimum investigate:

- block/unblock records and block-store snapshots/cursors
- threat-intel indicators and enforcement-derived state
- organization public keys / tier keys
- global-node revocation state
- canonical trust snapshots
- routing/provider policy records
- node/peer metadata where it influences security decisions
- challenge/PoW mesh state if replicated
- configuration or administrative data that is propagated between nodes
- certificate/key material if any mesh mechanism distributes it

For each namespace fill a binding table:

| Namespace | Authority | Transport/replica | Consistency | Version/order key | TTL/expiry | Conflict rule | Partition read | Partition write | Enforcement effect |
|-----------|-----------|-------------------|-------------|-------------------|------------|---------------|----------------|-----------------|--------------------|

No security-relevant replicated namespace should remain documented only as "eventually consistent" without the rest of the contract.

## Step 2: Classify authority explicitly

Every namespace must be one of:

- **local authoritative** — local node owns state; replication is informational/best effort
- **advisory distributed** — remote data may inform policy but cannot directly establish canonical trust
- **canonical consensus-backed** — only committed canonical state is authoritative
- **derived cache/materialization** — may be reconstructed only from an authoritative source and must carry freshness/version metadata

If a namespace does not fit, define a precise additional category rather than allowing ambiguous mixed authority.

Add code-level types or wrapper metadata where raw records currently cannot reveal their authority/provenance.

## Step 3: Reconcile Raft/DHT documentation with actual implementation

Audit current code under `crates/synvoid-mesh/src/mesh/raft/`, canonical-trust readers, and DHT publication paths.

Determine whether existing MESH-15 text still describes the current implementation. Specifically verify:

- leader/election behavior
- quorum definition and membership source
- commit index/term handling
- read behavior without quorum
- write behavior without quorum
- membership changes and node loss
- whether DHT canonical namespaces are strictly derived from committed Raft state

Then do one of:

- close MESH-15 as stale with code/test evidence; or
- rewrite it as a precise current limitation with a concrete failure mode and operational response.

Do not "solve" canonical write unavailability by accepting unsigned/advisory/DHT writes as canonical.

## Step 4: Define partition behavior per namespace

For canonical consensus-backed data:

- writes without required quorum return a typed `QuorumUnavailable`/equivalent failure
- the caller must not report success or queued canonical commit
- reads may use last committed state only according to an explicit freshness policy
- stale canonical state must be classified/observable
- no uncommitted local mutation may masquerade as canonical state

For advisory/eventual data:

- local operation may proceed where policy allows
- propagation status is best effort
- conflict/duplicate handling is deterministic
- enforcement use is gated by local policy/provenance

For local authoritative state:

- remote copies must not overwrite local authority unless the contract explicitly grants that power.

## Step 5: Normalize versioning and conflict rules

For each namespace, prefer explicit version/order metadata such as:

- Raft `(term, index)` for canonical committed records
- source identity + monotonic sequence for source-scoped event streams
- content/version digest for immutable records

Avoid security-critical "last writer wins by wall-clock timestamp" unless unavoidable and documented with skew bounds.

If timestamps remain necessary for TTL/freshness:

- use safe/saturating timestamp helpers
- define accepted future skew
- define behavior for expired/future-dated records
- ensure future timestamps cannot make malicious state immortal

## Step 6: Make expiry semantics explicit

For every expiring enforcement/advisory record specify:

- who sets TTL
- maximum accepted TTL
- whether TTL survives replication unchanged or is converted to absolute expiry
- how clock skew is bounded
- cleanup behavior
- whether expiry itself is replicated or derived locally
- how unblock/revocation interacts with expiry

Add tests for boundary values, zero/max TTL, clock-skew cases, replay of expired state, and restart persistence/hydration.

## Step 7: Preserve policy gate between distributed evidence and enforcement

Audit all consumers of remote block/threat/routing state.

No newly received advisory datum may directly invoke an enforcement mutation without passing through the established trust/provenance/policy gate.

Where current call sites bypass the canonical policy helper:

- route them through the existing policy API
- preserve local operator/manual authority semantics
- add a guard/source test preventing direct remote-to-enforcement mutation paths

Do not broaden request-path capabilities as part of this work.

## Step 8: Typed mutation/propagation outcomes

Update control-plane/admin/mesh APIs so results distinguish at least:

- local mutation applied
- local mutation rejected
- canonical commit completed
- propagation queued/best effort
- propagation failed/partial
- quorum unavailable
- stale/not-authoritative source rejected

Reuse existing `AdminMutationResult`/propagation types where appropriate rather than creating parallel success envelopes.

Operator-visible success must not imply distributed/canonical completion unless that state is actually proven.

## Step 9: Partition/rejoin tests

Build deterministic in-process/integration tests using test transports or controlled peers; avoid requiring a large external cluster.

Required scenarios include:

- canonical quorum available: write commits and derived replicas update
- canonical quorum lost: write fails typed/fail-closed
- reads during partition follow documented freshness policy
- partition heals: committed state converges without accepting stale divergent writes
- duplicate/replayed events do not reapply
- source sequence gaps use snapshot/fallback behavior where defined
- stale canonical snapshot is classified and cannot silently authorize new trust decisions
- expired advisory/enforcement records do not resurrect after rejoin
- remote advisory state remains policy-gated
- unblock/revocation ordering is preserved across disconnect/rejoin

If an existing Raft test harness can simulate membership/partition, extend it rather than creating another distributed-test framework.

## Step 10: Observability

Expose bounded signals for:

- canonical quorum availability
- current term/commit index where safe/useful
- canonical snapshot age/freshness class
- rejected stale/untrusted records
- replay/duplicate suppression
- propagation partial/failure outcomes
- convergence lag where measurable

Do not expose key material, raw tokens, or high-cardinality peer-specific metric labels.

## Documentation reconciliation

Update relevant documents so they agree with the new contract:

- `architecture/mesh_deep_dive.md`
- `architecture/mesh_trust_domains.md`
- blocklist convergence docs
- `docs/THREAT_INTEL.md`
- admin/control-plane authority docs
- `architecture/layer_3_5_deep_dive.md` if MESH-15 language changes
- `architecture/runtime_operations_drill.md`
- release/final-surface residual-risk sections

A single `distributed_state_contract.md` should be the authoritative matrix; other docs should link to it instead of redefining consistency semantics independently.

## Acceptance criteria

Phase 23 is complete when:

- every security-relevant replicated namespace is present in the contract matrix
- authority, consistency, ordering, expiry, conflict, partition-read, partition-write, and enforcement semantics are explicit
- canonical DHT material cannot become independent authority during a partition
- quorum-unavailable canonical writes fail with a typed result and cannot be reported as success
- current Raft behavior and MESH-15 documentation are reconciled with code/test evidence
- advisory threat/distributed state remains policy-gated before enforcement mutation
- expiry/replay/rejoin behavior is tested for block/threat/canonical trust state
- admin/control-plane propagation responses truthfully distinguish local, best-effort, and canonical outcomes
- distributed-state metrics are bounded and do not leak secrets
- existing Phase 5 blocklist convergence invariants remain green

## Rejection criteria

Reject an implementation that:

- weakens canonical authority to a DHT/local fallback during quorum loss
- uses wall-clock last-writer-wins for trust/revocation state without a justified contract
- reports queued propagation as canonical success
- adds another consensus subsystem
- lets advisory remote records mutate enforcement directly
- treats partition tests as optional documentation-only work
- duplicates consistency rules across several docs without a canonical matrix

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check --features mesh
cargo test -p synvoid-mesh
cargo test --test request_path_capability_boundary_guard --features mesh
cargo test --test manual_enforcement_provenance_guard --features mesh
```

Also run the existing blocklist convergence, canonical trust/freshness, threat-intel policy-gate, and admin mutation propagation tests plus the new partition/rejoin scenarios.
