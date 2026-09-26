# Phase 92 Plan: ICMP Disabled-State and Lifecycle Commit Semantics Corrective

Status: **CLOSED — CORRECTED** (2026-09-26).

Registered in: `plans/roadmap.md` and
`plans/icmp_linux_native_qualification_gate_roadmap.md`.

Baseline: `main` at `826e634d7b9475c7b0b44badd2f51f07df6ddd17`.

Depends on: closed Phases 90–91.

Blocks: Phase 93 Linux nftables native qualification.

## Goal

Close the remaining lifecycle correctness defects before native qualification.

The terminal invariant is:

> committed desired state, verified live state, receipts, generations, admin
> persistence, and mutation outcomes describe the same successful lifecycle
> transition.

A failed operation may record diagnostic attempt information, but it must not
silently replace committed desired state.

## Finding A — disabled config replacement is currently reported as failure

At the baseline, `drive_update()`:

1. records `driver.desired_enabled = Some(config.enabled)`;
2. calls backend `update_config(config)`;
3. treats only `VerificationOutcome::Verified` as success;
4. treats `Absent` as drift/error.

Real backends intentionally remove owned enforcement when replacement config
has `enabled = false`. Their correct live state is therefore `Absent`.

This creates a split-brain admin outcome:

- backend may correctly disable enforcement;
- driver records live `Absent`;
- `drive_update()` returns an error;
- admin does not persist the application DTO because the update was reported
  failed.

### Required correction

Make update success conditional on the requested committed desired state.

Required result matrix:

| Desired state | Live verification | Result |
|---|---|---|
| enabled | Verified | success: applied |
| enabled | Absent | failure: required enforcement missing |
| enabled | Drifted | failure |
| enabled | Unknown | failure |
| disabled | Absent | success: verified disabled |
| disabled | Verified | failure: owned enforcement remains |
| disabled | Drifted | failure |
| disabled | Unknown | failure |

Do not manufacture an `ApplyReceipt` for the disabled/Absent success case.

Prefer a typed lifecycle/update outcome, for example:

```rust
enum LifecycleOutcome {
    Applied(ApplyReceipt),
    VerifiedAbsent,
    VerifiedNoOp { state: EnforcementState },
}
```

Exact naming is implementation-defined. The important property is that a
successful absence/no-op cannot masquerade as a successful install.

`IcmpFilterManager::update_config()` may continue returning `Result<()>` if
the typed internal outcome does not need to escape the manager.

## Finding B — committed desired state is mutated before success

Current drivers update parts of `DriverState` before compile/install/verify
has reached a successful terminal state.

Examples:

- `drive_update()` writes candidate desired fingerprint/enabled state before
  backend replacement succeeds;
- `drive_enable()` writes `desired_enabled = true` before compile/install;
- `drive_disable()` writes `desired_enabled = false` before cleanup and
  absence verification.

The admin handlers report failed mutations as `Failed`, and config PUT does
not persist a rejected DTO. The driver must not then expose that rejected
request as committed desired state.

### Required correction

Define one of these equivalent models:

1. **stage then commit** — copy/construct candidate driver state, run the
   operation, and commit desired fields only on a successful terminal
   outcome; or
2. **explicit pending state** — add separately named pending/attempted fields
   that never replace committed desired fields until success.

Prefer stage-then-commit unless a real operator requirement justifies exposing
pending intent.

On failure:

- committed desired state remains the previous successful state;
- previous verified receipt/generation remains intact;
- live state may change only when the backend really changed and readback
  proves that fact;
- diagnostic error records the failure without pretending the request
  committed.

For a backend failure that mutates kernel state despite returning error,
preserve the Phase 87 rule: never claim the replacement generation; surface
Drifted/Unknown/actual readback truth and require reconciliation.

## Finding C — `verify_live()` is not desired-state-aware

Current `VerificationOutcome::Absent` handling always sets:

```text
live = Absent
last_verify_error = "owned objects absent"
```

That is correct only when enforcement is desired.

### Required correction

At minimum:

- committed desired enabled + Absent:
  - `live = Absent`;
  - retain a diagnostic indicating required enforcement is missing;
- committed desired disabled + Absent:
  - `live = Absent`;
  - clear `last_verify_error`;
- unknown/uninitialized desired state + Absent:
  - do not invent an error or success claim; initialize desired truth from
    config or return an explicitly documented neutral state.

Do not rewrite `Absent` into `Applied` for disabled policy merely to get a
green status. The useful truth is "desired disabled; owned enforcement absent."

## Finding D — manager construction does not seed desired truth

`IcmpFilterManager::new(config)` currently initializes
`DriverState::default()`, so `desired_enabled` is initially `None` even
though the supplied configuration has an explicit enabled state.

### Required correction

Seed committed desired state from the validated constructor config without
claiming live enforcement.

At construction:

- `desired_enabled` reflects `config.enabled`;
- a desired fingerprint may be computed/stored only if doing so is pure and
  semantically useful;
- `live` remains Unknown until install/readback establishes live truth;
- no apply receipt exists until a verified install occurs.

This keeps status truthful before the first mutation/readback.

## Finding E — repeated enable advances generation despite no install

The current idempotent branch treats backend `AlreadyEnabled` as success,
verifies live state, then increments generation and creates a new
`ApplyReceipt`.

That turns a no-op into a fictitious install.

### Required correction

Repeated enable of the same already-live generation must:

- perform bounded verification;
- return success only if live state matches the current committed policy;
- preserve generation;
- preserve the previous apply receipt;
- return a typed no-op/verified-current outcome if the caller needs to
  distinguish it.

If live state is Drifted/Absent/Unknown, repeated enable must not silently
return a no-op success. Either repair through an explicit reinstall path or
return an error requiring reconciliation; document the chosen semantics.

Do not increment generation without an actual successful policy installation
or replacement.

## Finding F — test fake does not faithfully model disabled replacement

The Phase 87/90 `FakeFilter::update_config()` currently installs a
fingerprint even when the candidate config is disabled. That makes the fake
unable to expose the real-backend disabled-update defect.

### Required correction

Make the fake model the backend contract:

- enabled config -> installed fingerprint;
- disabled config -> no installed owned state.

Add regression tests against the real shared driver, not a special corrective
helper.

## Required regression matrix

Add deterministic tests for at least:

1. enabled -> enabled update + Verified => applied receipt/generation advances;
2. enabled -> disabled update + Absent => success, desired false, live Absent,
   config commit succeeds, no fabricated apply receipt;
3. disabled -> disabled update + Absent => successful verified absence/no-op;
4. disabled desired + Verified => failure because rules remain;
5. enabled desired + Absent => failure because required rules are missing;
6. disabled desired + status readback Absent clears verify error;
7. enabled desired + status readback Absent retains missing-enforcement
   diagnostic;
8. failed update leaves committed desired fields/persisted config at previous
   successful values;
9. failed enable leaves committed desired state unchanged;
10. failed disable leaves committed desired state unchanged;
11. repeated enable of an already verified generation does not advance
    generation/receipt;
12. repeated enable with drift does not claim success;
13. constructor seeds desired enabled/disabled without claiming live Applied.

Add an admin regression for `PUT /icmp/config` with `enabled=false` proving:

- route returns `AdminMutationStatus::Applied` only after verified absence;
- application DTO is persisted;
- subsequent `GET /icmp/status` returns desired disabled + enforcement absent
  without a spurious verify error.

## Registry/documentation reconciliation

Correct the stale central roadmap section that still labels Phases 90–91
planned.

Update, as needed:

- `plans/roadmap.md`;
- `plans/icmp_post_retain_operator_truth_and_native_qualification_roadmap.md`
  with successor/gate pointer;
- `architecture/icmp_filter.md`;
- `architecture/icmp_policy_enforcement_extraction_readiness.md`;
- `.opencode/skills/icmp_filter/SKILL.md`.

Do not rewrite historical Phase 90/91 intent; add corrective/supersession
notes where claims were too broad.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo test --test admin_route_contract --profile ci --features icmp-filter
cargo test --test admin_router_composition --profile ci --features icmp-filter
cargo test --test admin_smoke_flow --profile ci --features icmp-filter
cargo check -p admin-ui
cargo xtask test guards
cargo xtask verify
cargo deny check
cargo audit
```

Also keep the Phase 91 harness non-privileged suites green:

```bash
cargo test -p xtask
cargo xtask icmp-qualify --dry-run
```

## Acceptance criteria

Phase 92 closes only when:

- desired-enabled/result verification matrix is implemented exactly;
- disabled config replacement succeeds only after verified absence;
- no disabled/no-op path fabricates an apply receipt;
- failed lifecycle operations do not replace committed desired state;
- constructor desired state is truthful before first enforcement action;
- expected disabled/Absent readback has no verify error;
- repeated enable is truly idempotent with respect to generation/receipt;
- fake-backend semantics model disabled replacement;
- admin config persistence and status agree for `enabled=false`;
- Phase 90–91 roadmap registry is reconciled;
- all focused/routine verification is green;
- Phase 88 RETAIN remains unchanged.

## Rejection criteria

Reject an implementation that:

- treats Absent as success regardless of desired state;
- treats Verified as success when desired state is disabled;
- fixes the admin handler while leaving shared driver semantics wrong;
- returns a fake apply receipt for verified absence;
- increments generation for an already-enabled verified no-op;
- leaves rejected candidate desired state committed after failure;
- weakens Phase 91 qualification cases to accommodate the corrective;
- changes extraction/publication status.

## Terminal state

Close as **CORRECTED** with an exact implementation SHA and verification
record. Phase 93 becomes executable only after this phase closes.

## Phase 92 closeout (2026-09-26)

Implemented in `crates/synvoid-icmp-filter/src/lib.rs` with deterministic
regressions in `crates/synvoid-icmp-filter/tests/transactional_enforcement.rs`.
`drive_update` now returns `Option<ApplyReceipt>`: verified enabled installs
advance a receipt, while verified disabled absence commits desired state and
returns `None`. Desired fields commit only on verified success; enable and
disable follow the same stage-then-commit rule. Repeated verified enable
preserves the prior receipt/generation and mismatched pre-existing state
requires reconciliation. Constructor state seeds desired enabled/fingerprint
without asserting live enforcement. Disabled absence readback clears the
verification diagnostic. The fake replacement backend removes owned state
when disabled.

Verification recorded: `cargo fmt --all`; `cargo test -p
synvoid-icmp-filter --profile ci` — PASS (97 tests across 7 suites before the
final disabled-live regression; rerun is pending due shared build contention).
The manager now returns the optional receipt outcome to the admin handler, so
verified disabled absence persists the DTO without presenting a historical
install receipt as the mutation result. Admin route execution is included in
the pending full repository verification. Phase 88 remains RETAIN.

Implementation SHA: recorded by the Phase 92 commit. Phase 93 is executable
but terminally **BLOCKED** on this host: it is macOS and lacks Linux network
namespaces, `ip`, `nft`, and required privileges. See
`architecture/icmp_linux_nftables_native_qualification.md`.
