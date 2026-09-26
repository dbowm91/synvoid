# Phase 90 Plan: ICMP Operator Enforcement Truth and Admin Contract Reconciliation

Status: planned (2026-09-26).

Registered in: `plans/roadmap.md` and
`plans/icmp_post_retain_operator_truth_and_native_qualification_roadmap.md`.

Baseline: `main` at `0c8d3cac2fb214932c22dc360057acdad3c44c98`.

Depends on: closed Phases 85–88. Phase 89 is an unrelated process-sandbox
corrective and is not a dependency.

## Goal

Make the operator-facing ICMP surface reflect the enforcement truth already
implemented in Phase 87.

The terminal invariant is:

> "enabled" is never presented as proof of enforcement; operator status is
> derived from the selected backend plus verified live state.

This phase also fixes the stale admin UI contract and ensures enable/disable
use the same transactional/verified lifecycle as config replacement.

## Finding A — manager enable/disable bypass the Phase 87 driver

Current manager behavior:

- `update_config()` uses `drive_update(..., &mut self.driver)`;
- `enable()` calls `self.filter.enable()` directly;
- `disable()` calls `self.filter.disable()` directly.

Consequences:

- kernel state can change without `DriverState` advancing;
- `report()` may remain `Unknown` or retain an old receipt after a successful
  enable/disable;
- a later status endpoint cannot truthfully rely on `report()` unless every
  lifecycle operation participates in the same state machine.

### Required correction

Add one manager-owned lifecycle path for:

- enable current policy;
- disable current policy;
- replace/update policy.

Do not duplicate backend-specific lifecycle logic in admin handlers.

The exact API is implementation-defined, but the state machine must capture:

- desired enabled/disabled state;
- desired generation/fingerprint when enabled;
- last verified apply receipt;
- selected backend;
- live state;
- last verification error.

An enable succeeds only when installation plus verification succeeds.
A disable succeeds only when owned enforcement is verified absent, or returns
an explicit Unknown/Drifted/error disposition when absence cannot be proven.

Retaining the previous apply receipt as historical information is acceptable,
but the report must make clear that live desired state is disabled/Absent.

Add deterministic fake-backend tests for enable/disable failure stages just as
Phase 87 did for replacement.

## Finding B — `/icmp/status` serves compatibility state, not enforcement state

Current `get_status` reads:

- `is_enabled()`;
- compatibility `status()/FilterStatus`;
- requested config `filter_type`.

It does not consume `report()` or `verify_live()`.

It can therefore report `enabled` after external deletion/drift, and the
`backend` field can describe the requested `Auto` choice instead of the
backend actually selected.

### Required correction

Make `GET /icmp/status` consume the manager's authoritative enforcement
report.

Status should expose at least:

- whether the subsystem is configured;
- desired enabled/disabled state;
- actual selected backend;
- enforcement state: `applied`, `absent`, `drifted`, or `unknown`;
- desired generation;
- desired fingerprint as a hex/string representation (do not expose a raw
  `u64` fingerprint to JavaScript and invite precision loss);
- last verified apply receipt where present;
- last verification error/detail where present.

Keep any compatibility `enabled` / `status` fields only if needed for
existing consumers. If retained:

- document `enabled` as desired/configured state, not proof of enforcement;
- make `status` map to the verified enforcement state, not to a backend-local
  boolean.

### Live verification behavior

A status request should refresh live state when doing so is safe and bounded.

Preferred behavior:

1. take the manager write lock only for the duration required by
   `verify_live()` and report update;
2. perform readback only — no rule mutation;
3. release the lock before JSON serialization/other work;
4. return `unknown` plus diagnostic detail if readback fails;
5. never convert a readback error to `applied` from cached `enabled`.

If implementation evidence shows that unconditional readback is too expensive
for an authenticated status GET, introduce an explicit freshness contract
(e.g. cached report + `refresh=true` or a dedicated verify endpoint). Do not
fall back to ambiguous booleans. Document and test whichever contract is
chosen.

## Finding C — packet statistics are fabricated

Current status creates an `IcmpStats` object filled with six zeroes whenever
the filter is locally enabled, while logging that counters are not available.

Zero is a real measurement and therefore not an honest representation of
"unsupported/unobserved."

### Required correction

Use one of these truthful outcomes:

1. return `stats: null` unless the selected backend supplies real,
   evidence-backed packet counters; or
2. introduce a typed availability wrapper that distinguishes
   `unsupported`/`unavailable` from measured counters.

Do not synthesize zeros.

Do not broaden this phase into a cross-backend packet-counter implementation.
The eBPF-specific counter API may remain backend-specific unless a clean common
contract is already justified.

## Finding D — backend inventory reports incomplete truth

`/icmp/backends` currently:

- calls `available_backends()`;
- maps every returned backend to `available: true`;
- derives `current_backend` from requested config `filter_type`.

This loses the Phase 86 distinctions among compiled, mechanism-present,
privileged/usable, and selected.

### Required correction

Project the Phase 86 probe/selection model into the admin response.

At minimum each platform-relevant backend entry should be able to expose:

- backend name;
- compiled into this build;
- usable on this host;
- reason when unusable;
- static capability summary if useful and cheap.

`current_backend` must come from the actual manager/report selected backend.

Keep the existing `available` field as a compatibility alias for
`usable` only if required by consumers; do not hardcode it.

The endpoint should describe relevant backends even when unusable when the
platform/build can identify them; an empty list must not be the only way to
express "compiled but insufficient privilege."

## Finding E — the admin UI models the wrong domain

`admin-ui/src/pages/icmp.rs` currently defines:

- status fields `active`, `backends_count`, `last_ping`;
- backend fields `node_id`, `address`, `latency_ms`, `last_seen`,
  `healthy`;
- config fields `interval_secs`, `timeout_secs`, `packet_size`.

Those are health-probe/ping concepts and do not match the ICMP firewall
server API.

The UI also treats `/icmp/backends` as a raw array even though the server
returns `IcmpBackendsResponse { backends, current_backend }`.

### Required correction

Rewrite the page around filtering/enforcement semantics.

The UI should show, where available:

- desired state (enabled/disabled);
- live enforcement state;
- selected backend;
- last successful applied generation/time;
- drift/unknown diagnostic;
- backend usability/probe reasons;
- policy/config summary relevant to ICMP filtering.

Remove node/latency/ping concepts from this page.

Do not optimistically set "Active" after an enable request merely because the
mutation request returned HTTP success. Re-fetch authoritative status after
enable/disable/config mutation.

Prefer typed serde response structs in the admin UI/API client rather than
manual `serde_json::Value` field probing for this security-sensitive status
contract.

## Finding F — mutation audit/result should reflect verified outcome

The enable/disable routes currently log resulting state as
`{"enabled": true/false}` after backend-local success.

After lifecycle reconciliation:

- only return `AdminMutationStatus::Applied` when the manager's operation
  reached its documented verified state;
- include selected backend/enforcement state in audit resulting-state data;
- on drift/unknown/verification failure, return `Failed` with the state/detail
  preserved for diagnostics;
- keep persistence semantics separate from kernel-enforcement truth.

For config updates, do not persist a new enabled policy as "applied" if the
transactional driver rejects installation/verification. Preserve the Phase 87
rollback discipline.

## API compatibility and schema

Update `utoipa` schemas and OpenAPI registration for new/changed DTOs.

Add explicit serialization tests that pin:

- configured but disabled;
- applied;
- absent after disable;
- drifted;
- unknown/readback failure;
- explicit backend selected;
- `Auto` requested but a concrete backend selected;
- stats unavailable => null/typed-unavailable;
- backend compiled but unusable with reason.

Do not expose internal error types directly on the wire.

## Tests and guards

Add focused coverage in the smallest appropriate test targets.

Required cases:

1. manager enable advances verified lifecycle state;
2. manager disable reaches verified Absent;
3. failed enable does not create an apply receipt;
4. failed disable does not claim Absent;
5. external drift reflected by status verification;
6. status backend is actual selected backend, not requested `Auto`;
7. no fabricated all-zero stats object;
8. backend list exposes unusable reason;
9. admin wire serialization/OpenAPI schema remains stable;
10. admin UI parses the server's object-shaped backend response;
11. admin UI re-fetches after mutation rather than optimistic Active state;
12. source/guard check prevents the status handler from returning to
    compatibility `FilterStatus` as its authority.

If a fake/injected ICMP manager is needed for route tests, introduce the
smallest test seam rather than requiring root/nftables in ordinary admin tests.

## Documentation reconciliation

Update current authority as needed:

- `architecture/icmp_filter.md`;
- `architecture/icmp_policy_enforcement_extraction_readiness.md` with a
  post-RETAIN operator-truth note;
- `docs/ADMIN_UI.md` if the ICMP page is documented there;
- admin/OpenAPI docs;
- `.opencode/skills/icmp_filter/SKILL.md`;
- this plan and `plans/roadmap.md` on closure.

The Phase 88 **RETAIN** extraction decision remains unchanged.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo test --test admin_route_contract --profile ci --features icmp-filter
cargo test --test admin_router_composition --profile ci --features icmp-filter
cargo test --test admin_smoke_flow --profile ci --features icmp-filter
cargo check -p synvoid-admin-ui
cargo xtask test guards
cargo xtask verify
```

Use the repository's actual admin-ui package name/command if it differs at
implementation time.

## Acceptance criteria

- enable/disable/config update share one manager lifecycle state machine;
- `EnforcementReport` is authoritative for operator enforcement state;
- status can distinguish Applied/Absent/Drifted/Unknown;
- selected backend is reported truthfully;
- no zero-filled synthetic packet stats remain;
- backend inventory exposes probe truth;
- admin mutations do not claim Applied without verified lifecycle success;
- the ICMP admin UI represents filtering, not ping health;
- UI and server backend response shapes agree;
- OpenAPI/tests pin the new contract;
- routine admin/status reads cannot mutate firewall policy;
- RETAIN extraction disposition remains in force.

## Rejection criteria

Reject implementation that:

- merely renames `enabled` to `active`;
- calls `report()` without fixing direct enable/disable driver bypass;
- performs firewall mutation from GET/status;
- reports requested `Auto` as the active backend;
- retains fabricated zero packet counters;
- leaves the UI on node/latency/ping concepts;
- treats HTTP 200 from enable/disable as proof of enforcement without
  re-reading authoritative status;
- expands into publication/extraction work.
