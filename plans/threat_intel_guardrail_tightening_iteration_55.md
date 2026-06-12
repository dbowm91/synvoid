# Threat-Intel Guardrail Tightening Cleanup — Iteration 55

## Purpose

Iteration 54 established the consumer/actionability taxonomy and made `handle_incoming_threat` policy-gated before enforcement mutation. The remaining cleanup is mechanical guardrail precision.

The current guardrail allowlists `crates/synvoid-mesh/src/mesh/threat_intel.rs` for raw threat-intel lookup tokens because that file defines the raw lookup APIs and contains diagnostic/shadow/policy-composed compatibility paths. However, the same file also contains the primary enforcement entry point: `handle_incoming_threat`.

This cleanup should tighten the source-scan guardrail so `threat_intel.rs` is not globally exempt from raw-lookup enforcement. Raw lookups should remain allowed only inside explicitly non-enforcement functions/regions.

## Current Known State

- `architecture/threat_intel_consumer_actionability.md` is the canonical consumer inventory.
- `handle_incoming_threat` calls `evaluate_incoming_threat_policy()` before enforcement mutations.
- Enforcement mutations check `ThreatIntelConsumerAction::PermitAction` before block/rate-limit/suspicious/throttle actions.
- Threat-intel enforcement block writes use `MeshThreatIntelPolicyGated` provenance.
- Shadow-only behavior is documented as non-mutating.
- `tests/threat_intel_consumer_actionability_guard.rs` exists.
- The guardrail currently checks raw lookups in enforcement-sensitive directories but globally allowlists `threat_intel.rs`.

The cleanup target is not the runtime path; it is guardrail sharpness and future regression resistance.

## Non-Goals

Do not redesign threat-intel policy composition.

Do not remove raw lookup APIs.

Do not move all threat-intel functions into separate files unless trivially useful.

Do not change blocklist semantics.

Do not change mesh-ID scope.

Do not change fail-open/fail-closed policy semantics unless an actual bug is found.

Do not weaken local-origin/admin/manual authority paths.

## Phase 1 — Inventory Raw Lookup Locations Inside `threat_intel.rs`

Search within `crates/synvoid-mesh/src/mesh/threat_intel.rs` for:

- `lookup_local_indicator(`
- `lookup_local_indicator_by_ip(`
- `lookup_threat_indicator_in_dht(`
- `diagnostic_lookup_local_indicator`
- `diagnostic_lookup_local_indicator_by_ip`
- `diagnostic_lookup_threat_indicator_in_dht`
- `lookup_*_policy_composed`
- `lookup_*_policy_strict`
- `evaluate_indicator_policy_shadow`
- `handle_incoming_threat`
- `apply_rate_limit_mesh_action_after_policy_permit`
- `apply_suspicious_mesh_action_after_policy_permit`

Classify each occurrence as one of:

- raw lookup API definition;
- diagnostic alias definition;
- policy-composed compatibility fallback;
- strict policy wrapper;
- shadow-only comparison;
- unit test;
- enforcement path;
- enforcement helper.

Only the first five categories should be allowlisted in production code.

## Phase 2 — Replace File-Level Allowlist With Function-Level Allowlist

Update `tests/threat_intel_consumer_actionability_guard.rs`.

Remove this broad allowlist behavior for raw lookup checks:

```rust
"crates/synvoid-mesh/src/mesh/threat_intel.rs",
```

Replace it with a function/region-level allowlist.

Suggested approach:

1. Parse `threat_intel.rs` into named function bodies using a lightweight brace-depth scanner.
2. For each raw lookup token occurrence, identify the containing function name.
3. Permit raw lookup only if the containing function is allowlisted.

Suggested allowlisted function names:

- `lookup_local_indicator`
- `lookup_local_indicator_by_ip`
- `lookup_threat_indicator_in_dht`
- `diagnostic_lookup_local_indicator`
- `diagnostic_lookup_local_indicator_by_ip`
- `diagnostic_lookup_threat_indicator_in_dht`
- `lookup_threat_indicator_policy_composed`
- `lookup_local_indicator_policy_composed`
- `lookup_local_indicator_by_ip_policy_composed`
- `lookup_threat_indicator_policy_strict`
- `lookup_local_indicator_policy_strict`
- `lookup_local_indicator_by_ip_policy_strict`
- `evaluate_indicator_policy_shadow`

If some policy/shadow implementation uses helper functions, include only those helpers after confirming they are not enforcement-bearing.

Do not allow raw lookup calls inside:

- `handle_incoming_threat`
- `apply_rate_limit_mesh_action_after_policy_permit`
- `apply_suspicious_mesh_action_after_policy_permit`
- `handle_hot_threat_gossip`
- `apply_sync`
- `handle_mesh_message`
- any function that calls block-store mutation directly because of remote advisory input.

## Phase 3 — Add Explicit Enforcement-Function Raw Lookup Denylist

Add a second guardrail check for high-value functions.

Deny raw lookup tokens inside these functions:

- `handle_incoming_threat`
- `apply_rate_limit_mesh_action_after_policy_permit`
- `apply_suspicious_mesh_action_after_policy_permit`
- any helper with `_after_policy_permit` suffix, unless it only consumes an already gated decision and does not perform lookup.

This test should fail even if the file is otherwise allowlisted.

Recommended failure text:

```text
Raw threat-intel lookup found inside enforcement function `{function}`.
Enforcement functions must consume `IncomingThreatPolicyGate` / PermitAction results, not raw advisory presence.
```

## Phase 4 — Add Simulated Regression Tests

Add guardrail self-tests proving the scanner catches the exact class of bug.

Examples:

```rust
#[test]
fn simulated_raw_lookup_inside_handle_incoming_threat_is_rejected() { ... }
```

```rust
#[test]
fn simulated_raw_lookup_inside_policy_composed_fallback_is_allowed() { ... }
```

```rust
#[test]
fn simulated_raw_lookup_definition_is_allowed() { ... }
```

```rust
#[test]
fn simulated_raw_lookup_inside_after_policy_permit_helper_is_rejected() { ... }
```

The goal is to validate the guardrail logic, not runtime behavior.

## Phase 5 — Keep Existing Policy-Gate Ordering Test

Keep `handle_incoming_threat_is_policy_gated()`.

It still has value because it verifies that block mutation appears after `evaluate_incoming_threat_policy()`.

But treat it as complementary, not sufficient:

- policy-gate ordering proves a gate exists before mutation;
- raw-lookup denylist proves raw advisory lookups cannot be added inside the enforcement body.

Update comments accordingly.

## Phase 6 — Diagnostic Alias Documentation

Ensure raw lookup APIs and diagnostic aliases have clear comments.

Desired language:

```rust
/// Diagnostic-only raw lookup. Not safe for enforcement/actionability decisions.
/// Enforcement consumers must use evaluate_incoming_threat_policy or strict policy-composed APIs.
```

For policy-composed fallback APIs, document:

```rust
/// Read-only compatibility helper. Falls back to raw lookup when no policy context exists.
/// Do not treat returned indicator presence as actionability.
```

For strict APIs, document:

```rust
/// Enforcement-safe read helper. Returns None when policy context is unavailable.
```

## Phase 7 — Consumer Inventory Doc Cleanup

Update `architecture/threat_intel_consumer_actionability.md` if needed.

Clarify:

- raw lookup definitions live in `threat_intel.rs`, but are not allowed in enforcement functions;
- guardrail uses function-level allowlisting inside `threat_intel.rs`;
- `handle_incoming_threat` is both policy-gated and raw-lookup-denied;
- policy-composed fallback methods are read-only and cannot be treated as actionability.

Update `AGENTS.md` rule 9 if needed to mention the function-level guardrail.

## Phase 8 — Tests

Add/update tests in `tests/threat_intel_consumer_actionability_guard.rs`:

- `threat_intel_rs_raw_lookup_only_in_allowlisted_functions`
- `handle_incoming_threat_contains_no_raw_lookup_calls`
- `after_policy_permit_helpers_contain_no_raw_lookup_calls`
- `simulated_raw_lookup_inside_handle_incoming_threat_is_detected`
- `simulated_raw_lookup_inside_policy_composed_fallback_is_allowed`
- `simulated_raw_lookup_definition_is_allowed`
- keep existing `handle_incoming_threat_is_policy_gated`
- keep existing shadow/provenance checks

If function scanner is reusable, keep it local to the guard test and simple.

## Phase 9 — Verification Commands

Run focused checks:

```bash
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test threat_intel_boundary_guard
cargo test -p synvoid-mesh threat_intel
cargo test -p synvoid-mesh actionability
cargo test --test manual_enforcement_provenance_guard
cargo test --test mesh_id_boundary_guard
cargo test --lib --no-run
```

If docs-only changes are also touched, still run the guardrail tests.

## Acceptance Criteria

This cleanup is complete when:

1. `threat_intel.rs` is no longer globally allowlisted for raw lookup calls.
2. Raw lookup calls inside `threat_intel.rs` are allowed only in explicit non-enforcement function bodies.
3. `handle_incoming_threat` is explicitly checked to contain no raw lookup calls.
4. Action-bearing helper functions are checked to contain no raw lookup calls.
5. Policy-composed fallback and diagnostic raw lookup functions remain allowed and documented.
6. Existing policy-gate ordering guard remains in place.
7. Simulated regression tests prove the new scanner catches raw lookup in enforcement functions.
8. Consumer inventory docs and AGENTS guidance mention function-level raw lookup boundaries.
9. Existing shadow/provenance/actionability guardrails still pass.

## Notes for the Implementer

This is a guardrail precision pass. The runtime policy path already appears correct; the purpose is to prevent future edits from slipping raw advisory reads into enforcement functions because `threat_intel.rs` was broadly allowlisted.

The invariant is:

> File-level compatibility must not become function-level enforcement permission.
