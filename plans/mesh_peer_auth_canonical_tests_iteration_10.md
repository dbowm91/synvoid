# Mesh Peer Auth Canonical Status Test Hardening — Iteration 10

## Goal

Close the small gap left after Iteration 9. `CanonicalTrustReader` now has clearer freshness and revocation semantics, and `peer_auth.rs` has a staged `validate_peer_canonical_status(...)` helper. This pass should add explicit tests and documentation for that helper before migrating another mesh consumer.

The goal is not broader architecture work. The goal is confidence that the first consumer-facing canonical seam behaves intentionally for authorized, unauthorized, revoked, unknown/unavailable, and stale freshness cases.

## Non-Goals

Do not migrate `dht/key_policy.rs` yet.

Do not migrate `threat_intel.rs`, `proxy.rs`, YARA/WASM, or service consumers.

Do not reorganize `synvoid-mesh` modules.

Do not remove legacy `validate_peer_role(...)` behavior.

Do not remove `GlobalNodeRevocationList` or `RECORD_STORE_GLOBAL`.

Do not make stale or unavailable canonical state stricter across production call sites.

Do not introduce network, DHT, or Raft-cluster tests.

## Phase 1 — Document Current Helper Semantics

### Current Helper

`peer_auth.rs` now contains:

```rust
pub fn validate_peer_canonical_status(
    reader: &dyn CanonicalTrustReader,
    peer_node_id: &str,
    role: &crate::config::MeshNodeRole,
) -> Result<(), String>
```

It should be documented as a staged canonical-status helper, not a full peer authentication replacement.

### Required Rustdoc / Comments

Add rustdoc above the helper explaining:

- It checks canonical revocation status for all roles.
- It checks global-node authorization for global non-origin roles.
- It does not verify signatures, certificates, PoW, origin attestations, or timestamps.
- It does not replace `validate_peer_role(...)`.
- `Unknown` / `Unavailable` revocation currently preserves legacy permissive behavior.
- `Unknown` / `Unavailable` global authorization fails closed for global non-origin roles.
- Freshness is surfaced in errors but does not currently determine acceptance.

### Acceptance Criteria

A reader can understand exactly what the helper does and does not validate.

The documented behavior matches tests added in this pass.

## Phase 2 — Add Focused Tests For `validate_peer_canonical_status`

Add tests in `peer_auth.rs` using `StaticCanonicalTrustReader`.

### Required Test Cases

1. **Authorized global node passes**
   - Role: `GLOBAL`
   - Reader has `authorized_global_nodes` containing the peer ID.
   - No revocation entry.
   - Expected: `Ok(())`.

2. **Unauthorized global node fails**
   - Role: `GLOBAL`
   - Reader does not contain the peer ID in `authorized_global_nodes`.
   - Expected error includes `not authorized in canonical state`.

3. **Revoked global node fails before authorization success matters**
   - Role: `GLOBAL`
   - Reader contains peer ID in both `authorized_global_nodes` and `revoked_nodes`.
   - Expected error includes `revoked in canonical state`.

4. **Revoked edge node fails**
   - Role: `EDGE`
   - Reader contains peer ID in `revoked_nodes`.
   - Expected error includes `Edge node` and `revoked in canonical state`.

5. **Non-revoked edge node passes without global authorization**
   - Role: `EDGE`
   - Reader has no revocation entry.
   - Reader does not include global authorization.
   - Expected: `Ok(())`.

6. **Unavailable revocation freshness preserves permissive behavior for non-global role**
   - Role: `EDGE`
   - Reader freshness: `CanonicalFreshness::Unavailable`.
   - No revocation entry.
   - Expected: `Ok(())`.

7. **Unavailable global authorization fails closed**
   - Role: `GLOBAL`
   - Reader freshness: `CanonicalFreshness::Unavailable`.
   - No authorized-global entry.
   - Expected error includes `not authorized in canonical state` and freshness.

8. **Stale global authorization behavior is explicit**
   - Role: `GLOBAL`
   - Reader freshness: `CanonicalFreshness::Stale { age_ms: ... }`.
   - Reader contains authorized global node.
   - Expected: currently `Ok(())` because freshness is observed but not policy-enforcing in this pass.
   - Add a comment that future policy may tighten this.

9. **Global-origin role does not require global authorization in this helper if current logic excludes origins**
   - Role: `GLOBAL_ORIGIN` or equivalent composite.
   - Reader lacks authorized-global entry.
   - Expected behavior should match current helper logic. If this is not desired, update the helper intentionally and test the new behavior.

### Acceptance Criteria

Tests cover authorized, unauthorized, revoked, unknown/unavailable, and stale freshness behavior.

Tests make explicit whether `GLOBAL_ORIGIN` is intentionally exempt from global-node authorization in this helper.

No tests invoke real networking, DHT, or Raft.

## Phase 3 — Check Global Role Semantics

### Issue To Review

The helper currently checks global authorization when:

```rust
role.is_global() && !role.is_origin()
```

That means composite roles that are both global and origin may not require global authorization through this helper.

### Required Review

Inspect role definitions and intended meaning:

```bash
rg "struct MeshNodeRole|GLOBAL_ORIGIN|GLOBAL_EDGE|EDGE_ORIGIN|is_global|is_origin|is_edge" crates/synvoid-config crates/synvoid-mesh src
```

Decide whether `GLOBAL_ORIGIN` should require canonical global authorization in this helper.

Options:

1. Keep current behavior and document why origin-global composite is handled elsewhere.
2. Change helper to require global authorization for any role with `role.is_global()`.
3. Add a narrower exception only if an existing invariant requires it.

Do not make this change silently.

### Acceptance Criteria

`GLOBAL`, `GLOBAL_EDGE`, and `GLOBAL_ORIGIN` behavior is intentional and tested.

If behavior changes, the test names make the new rule obvious.

## Phase 4 — Update Architecture Note

Update `architecture/mesh_trust_domains.md` with a short Iteration 10 note.

Suggested text:

```markdown
### Iteration 10 Canonical Helper Semantics

`peer_auth::validate_peer_canonical_status` is now test-covered as a staged consumer of `CanonicalTrustReader`. It checks canonical revocation for all roles and canonical global-node authorization for the configured global-role cases. It does not perform signature, certificate, PoW, timestamp, or full policy validation. Freshness is surfaced but not yet policy-enforcing; unavailable revocation preserves legacy permissive behavior, while unavailable global authorization fails closed for global-node authorization checks.
```

Adjust the text if Phase 3 changes global-role behavior.

### Acceptance Criteria

The design note accurately documents helper semantics after tests land.

The note does not claim broad production migration beyond the helper.

## Phase 5 — Optional: Rename Helper If Needed

If tests make it clear the helper is not validating full peer canonical status, consider a clearer name. Candidate names:

```rust
validate_peer_canonical_revocation_and_global_auth
check_peer_canonical_status
check_canonical_peer_admissibility
```

Do not rename if it causes unnecessary churn. Prefer tests/docs over naming churn unless the current name proves misleading.

### Acceptance Criteria

Either the helper name remains and rustdoc is precise, or the rename is low-churn and call sites/tests are updated.

## Validation Commands

Run focused checks:

```bash
cargo fmt --all --check
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh canonical --features mesh
cargo test -p synvoid-mesh peer_auth --features mesh
```

Then run broader mesh checks:

```bash
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broader checks fail for unrelated reasons, record the exact focused checks that passed and the unrelated failure.

## Completion Criteria

This iteration is complete when:

- `validate_peer_canonical_status` has precise rustdoc/comments;
- helper tests cover authorized, unauthorized, revoked, unavailable, stale, edge/non-global, and composite global-role behavior;
- global-role authorization semantics are explicit and tested;
- freshness behavior is documented but not over-enforced;
- no new consumer is migrated;
- no broad mesh module movement occurs;
- `architecture/mesh_trust_domains.md` records the helper semantics.

## Follow-Up Recommendation

After this test/hardening pass, the next real consumer migration can target `dht/key_policy.rs`. That pass should use `CanonicalTrustReader` to separate DHT key authority classification from advisory DHT/quorum mechanics without changing record propagation behavior.
