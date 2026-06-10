# Mesh DHT Ingress Context Wiring Cleanup — Iteration 14

## Goal

Clean up the Iteration 13 mismatch and fully wire the canonical-reader ingress context into the actual direct client DHT ingress paths.

Current state after Iteration 13:

- `DhtIngressPolicyContext` exists in `dht/ingress_policy.rs`.
- `DhtRecordIngressContext` can carry `Option<DhtIngressPolicyContext>`.
- `store_record_from_ingress` consults `check_dht_ingress_authority(...)` for non-local `Push` and `Announce` paths when a policy context is attached.
- The architecture note claims Push/Announce receive the injected context.
- The visible Push/Announce context construction paths do not yet attach a configured policy context.

This pass should make the implementation and architecture note agree.

## Non-Goals

Do not migrate service consumers (`threat_intel.rs`, `proxy.rs`, YARA/WASM).

Do not introduce the full `AdvisoryRecordSource` seam.

Do not broaden canonical gating to sync replay, snapshot apply, anti-entropy, quorum, local writes, or Raft apply paths.

Do not remove `RECORD_STORE_GLOBAL`.

Do not construct `SnapshotCanonicalTrustReader` inside `store_record_from_ingress` or other low-level validation functions.

Do not make unrelated DHT propagation/storage changes.

Do not require live Raft/DHT/networking in tests.

## Phase 1 — Confirm The Current Wiring Gap

Inspect the current context creation paths.

Run:

```bash
rg "DhtIngressPolicyContext|with_policy_context|policy_context\(|new_remote\(|IngressPath::Push|IngressPath::Announce|handle_record_announce|DhtRecordPush|DhtRecordAnnounce|store_record_from_ingress" crates/synvoid-mesh/src/mesh/dht crates/synvoid-mesh/src/mesh crates/synvoid-mesh/src/lib.rs
```

Confirm:

1. `store_record_from_ingress` consults the gate only for `Push` and `Announce` when context is attached.
2. `DhtRecordPush` currently builds `DhtRecordIngressContext::new_remote(... IngressPath::Push)` without attaching policy context.
3. `handle_record_announce` currently builds `DhtRecordIngressContext::new_remote(... IngressPath::Announce)` without attaching policy context.
4. No other production path unexpectedly attaches the context.

### Acceptance Criteria

The wiring gap is confirmed before changing code.

No broader candidate path is selected in this pass.

## Phase 2 — Add A RecordStoreManager-Level Policy Context Carrier

Add an optional ingress policy context carrier to `RecordStoreManager` or an existing state object reachable by both Push and Announce paths.

Preferred low-churn shape:

```rust
pub struct RoutingState {
    // existing fields...
    pub ingress_policy_context: Option<crate::dht::DhtIngressPolicyContext>,
}
```

or, if routing state is not the right owner, add a direct field on `RecordStoreManager` guarded by `RwLock`/`Arc` as appropriate.

Add methods:

```rust
pub fn set_ingress_policy_context(&self, ctx: Option<crate::dht::DhtIngressPolicyContext>) { ... }

pub(crate) fn ingress_policy_context(&self) -> Option<crate::dht::DhtIngressPolicyContext> { ... }
```

### Rules

- The default must be `None`, preserving legacy behavior.
- The setter must not construct canonical readers.
- Production code should receive a ready-made `DhtIngressPolicyContext` from a higher layer.
- Do not use global state.
- Do not expose concrete `SnapshotCanonicalTrustReader` from DHT modules.
- Keep clone semantics cheap: `DhtIngressPolicyContext` already holds `Arc<dyn CanonicalTrustReader>`.

### Acceptance Criteria

`RecordStoreManager` can carry an optional `DhtIngressPolicyContext`.

Default construction remains behavior-compatible.

Tests can inject a `StaticCanonicalTrustReader` through this carrier.

## Phase 3 — Attach The Context In Direct Client Ingress Paths

Update the direct client ingress context construction only.

### Push Path

In the `MeshMessage::DhtRecordPush` branch, after constructing:

```rust
let ingress_ctx = DhtRecordIngressContext::new_remote(... IngressPath::Push)
    .with_envelope_signature(has_auth);
```

attach:

```rust
let ingress_ctx = ingress_ctx.with_policy_context(self.ingress_policy_context());
```

or equivalent.

### Announce Path

In `handle_record_announce`, after constructing:

```rust
let ingress_ctx = DhtRecordIngressContext::new_remote(... IngressPath::Announce);
```

attach:

```rust
let ingress_ctx = ingress_ctx.with_policy_context(self.ingress_policy_context());
```

### Explicitly Do Not Attach Context To

- `apply_snapshot`
- `verify_and_apply_snapshot`
- `DhtSyncResponse` record application
- anti-entropy missing-record application
- local record creation
- quorum apply paths

### Acceptance Criteria

Push and Announce carry the configured context into `store_record_from_ingress`.

Disabled/default context still preserves legacy behavior.

Sync/replay/local/quorum paths remain unchanged.

## Phase 4 — Add Tests Proving Context Actually Reaches The Gate

Add tests around `RecordStoreManager` or the narrowest available unit boundary.

Required tests:

1. **Default manager preserves legacy behavior**
   - No ingress policy context set.
   - Push/Announce-style `DhtRecordIngressContext` or handler path does not reject solely because no reader exists.

2. **Configured Push rejects unauthorized canonical-required key**
   - Inject `DhtIngressPolicyContext::with_canonical_reader(Arc::new(StaticCanonicalTrustReader::new(Live)))` with no authorized global signer.
   - Use a canonical-required key such as `GlobalNodeProof` or equivalent.
   - Ensure `store_record_from_ingress` rejects when path is `Push` and signer/source is unauthorized.

3. **Configured Announce rejects unauthorized canonical-required key**
   - Same as above, but path `Announce` or through `handle_record_announce` if feasible.

4. **Configured advisory key remains accepted subject to existing validation**
   - Use an advisory key path that already passes existing signature/access checks.
   - Ensure canonical gate does not reject it.

5. **Sync/replay bypass remains unchanged**
   - Construct a `SnapshotSync` or `SyncResponse` context with the same configured policy context and a canonical-required key.
   - Verify the canonical gate is not consulted, or document if existing validation rejects for another reason.
   - The test should specifically prove this iteration did not broaden gating to sync/replay.

### Practical Test Guidance

If full record construction/signature validation is too heavy:

- factor the gate check inside `store_record_from_ingress` into a small `should_apply_ingress_canonical_gate(...)` or `check_record_ingress_canonical_gate(...)` helper and test that helper directly;
- keep the helper `pub(crate)` or private with tests in the same module;
- do not weaken existing signature/content-hash validation to make tests easier.

### Acceptance Criteria

Tests prove configured context reaches Push/Announce gate.

Tests prove default `None` remains legacy-compatible.

Tests prove sync/replay/local paths are not accidentally gated.

## Phase 5 — Fix Architecture Note Accuracy

Update `architecture/mesh_trust_domains.md` to match reality.

If Push/Announce are wired:

```markdown
### Iteration 14 DHT Ingress Context Wiring Cleanup

`RecordStoreManager` now carries an optional `DhtIngressPolicyContext` and attaches it to direct client Push/Announce ingress contexts. The existing `store_record_from_ingress` gate is therefore active for configured Push/Announce paths and remains inactive by default. Disabled context preserves legacy behavior. Sync/replay/local/quorum/Raft apply paths remain outside this gate.
```

If the implementation instead discovers wiring cannot be done cleanly:

```markdown
### Iteration 14 DHT Ingress Context Wiring Cleanup

The Iteration 13 architecture note was corrected: the gate exists but production Push/Announce paths do not yet receive a configured `DhtIngressPolicyContext`. Wiring remains deferred pending a higher-level carrier for the context.
```

### Acceptance Criteria

Architecture docs no longer overclaim.

The follow-up recommendation points to the next actual step.

## Phase 6 — Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh ingress_policy --features mesh
cargo test -p synvoid-mesh key_policy --features mesh
cargo test -p synvoid-mesh record_store --features mesh
cargo test -p synvoid-mesh record_store_message --features mesh
cargo test -p synvoid-mesh record_store_crud --features mesh
```

Then baseline seam checks:

```bash
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
```

Then broader checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks fail for unrelated reasons, record the focused checks that passed and the unrelated failure.

## Completion Criteria

This iteration is complete when:

- `RecordStoreManager` or equivalent owns an optional `DhtIngressPolicyContext` carrier;
- direct Push and Announce contexts attach that carrier before calling `store_record_from_ingress`;
- default/disabled context preserves legacy behavior;
- configured context actually reaches the Push/Announce gate;
- tests cover Push, Announce, advisory/default behavior, and sync/replay non-gating;
- no globals or deep reader construction are introduced;
- architecture docs accurately describe the final state.

## Follow-Up Recommendation

After this cleanup, add an `AdvisoryRecordSource` seam before migrating service consumers. Only consider expanding the ingress gate to additional remote paths after the Push/Announce path is stable and the context carrier is clearly owned by a higher-level mesh service or data-plane composition object.
