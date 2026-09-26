# Phase 83 Plan: ICMP Transactional Enforcement and State Verification

Status: planned.

Registered in: `plans/roadmap.md` and
`plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

Depends on: Phases 81–82.

## Goal

Turn the ICMP backend layer from "mutate rules and remember a boolean" into a
compile-before-mutate enforcement boundary with explicit apply receipts,
failure-safe replacement, backend-scoped ownership, and live-state
verification.

The key invariant is:

> A policy update must not destroy known-working enforcement merely because the
> replacement later fails to compile, install, or verify.

## Workstream A — compile policy before mutating kernel state

Add a backend compilation step that accepts the canonical Phase 81 policy and
the selected Phase 82 backend capabilities.

A compile result should identify at least:

- backend;
- normalized requested policy fingerprint;
- concrete operations/objects to install;
- exact support vs unsupported requirements;
- required privilege/mechanism facts;
- warnings that do not change semantics.

Do not silently emit a weaker rule set.

A possible shape is:

```text
PolicyCompileResult =
    Exact(EnforcementPlan)
  | Unsupported { requirements, reasons }
```

If a future use case genuinely needs degraded semantics, add an explicit
caller opt-in later; do not make degradation the default cleanup behavior.

## Workstream B — establish backend-scoped ownership identity

Every backend must own only the objects created for this ICMP policy.

Review and normalize:

- nftables table/chain/set identity;
- PF anchor identity;
- WFP provider/sublayer/filter identity;
- Windows Firewall rule grouping/prefix if retained;
- eBPF attachment/map identity.

Ownership must be specific enough that disable/update does not delete unrelated
operator rules or another process instance's objects accidentally.

Where persistent objects can survive process exit, define restart/recovery
semantics rather than relying on `Drop`.

## Workstream C — failure-safe replacement

Implement backend-specific replace semantics behind one high-level contract.

Preferred order:

1. validate and compile replacement completely;
2. prepare/stage new objects;
3. apply atomically if the platform supports transactions;
4. otherwise use a bounded staged replacement with explicit rollback;
5. verify resulting live state;
6. only then retire superseded objects and advance desired/applied state.

Backend expectations:

- nftables: use transactional/atomic batch semantics available through the
  chosen mechanism;
- WFP: use an engine transaction for related changes;
- PF: load/update an owned anchor in the safest replacement form supported by
  the target variant;
- optional eBPF: prepare maps/programs before switching attachment where
  practical.

On a replacement failure, retain the previous policy whenever the backend
allows it. If the backend cannot prove rollback, return `Unknown` or
`Drifted`; never continue reporting the new policy as enforced.

## Workstream D — separate desired, applied, and verified state

Replace the current status assumption that local `enabled` means enforcement.

The public/internal status contract should distinguish:

- desired policy;
- selected backend;
- last apply receipt;
- live verification state;
- last verification error/time if tracked;
- enforcement confidence/state.

A minimal state vocabulary should cover:

- `Applied` / verified;
- `Absent`;
- `Drifted`;
- `Unknown` / unverifiable.

Do not overpromise continuous monitoring. A state may be "verified at
timestamp/generation N" rather than continuously authoritative.

## Workstream E — live readback and drift detection

Add backend readback sufficient to verify owned objects.

The goal is not a general firewall parser. It is to answer:

> Does the backend currently contain the owned objects corresponding to the
> policy generation/fingerprint we believe we applied?

Use stable ownership metadata/identifiers where the platform supports it.

Readback should tolerate unrelated operator firewall state.

If exact semantic reconstruction is prohibitively expensive on one backend,
document the reduced verification guarantee and expose `Unknown` rather than
claiming exact verification.

## Workstream F — update/disable lifecycle semantics

Define idempotent behavior explicitly:

- applying the already-applied policy;
- disabling an already-absent policy;
- recovering after process restart with stale owned state;
- partial cleanup failure;
- privilege loss after initial install;
- external deletion/modification of owned rules.

Avoid treating benign idempotence as an exceptional "already enabled/disabled"
error if that complicates reconciliation. The exact API can remain compatible
through adapters while the new internal contract becomes idempotent.

## Workstream G — truthful observability

Audit `crates/synvoid-icmp-filter/src/metrics.rs`.

Current packet allow/block counter helper functions are not evidence of kernel
packet outcomes unless a backend supplies those counts.

Use one of these outcomes:

- wire counters only where real backend counters/maps are queried; or
- remove/rename packet-outcome metrics and expose apply/error/drift/verification
  metrics instead.

Keep metrics optional/caller-owned for eventual extraction. The core
enforcement contract should return structured events/receipts rather than
requiring the `metrics` crate.

## Workstream H — deterministic fake-backend failure tests

Create a backend test double that can inject failure at:

- compile;
- prepare;
- apply;
- commit;
- verify;
- old-policy cleanup.

Use it to prove replacement invariants without requiring root or native
firewalls in routine tests.

Required invariants include:

1. compile failure performs zero mutation;
2. prepare/apply failure does not mark new policy applied;
3. commit failure retains/reports previous state correctly;
4. verify mismatch yields Drifted/Unknown, not Applied;
5. cleanup failure is visible;
6. explicit disable is idempotent or has a documented compatible adapter;
7. status generation/fingerprint matches the policy actually installed.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo xtask test guards
cargo xtask verify
```

Native backend smoke tests may be added as ignored/manual harnesses only if
their privilege requirement and cleanup guarantees are explicit. Phase 84
records actual native proof.

## Acceptance criteria

- Every update compiles/validates before destructive mutation.
- Unsupported semantics fail explicitly.
- Owned firewall objects are namespace/scoped and unrelated rules are not
  touched.
- Replacement uses backend transaction/staging semantics with rollback where
  available.
- Local desired state and verified applied state are separate.
- Live verification can report Applied, Absent, Drifted, or Unknown.
- Apply failure cannot leave status claiming the replacement is active.
- Restart/stale-state behavior is specified.
- Packet metrics are evidence-backed or removed/renamed.
- Routine deterministic failure-injection tests prove the state machine.

## Rejection criteria

Reject the phase if it:

- deletes old enforcement before compiling the replacement;
- uses `enabled: bool` as the only enforcement truth;
- treats logging a backend error as rollback;
- verifies by reading only in-process rule IDs;
- deletes broad firewall state outside the owned namespace;
- claims packet allow/block counts without backend evidence;
- hides verification failure behind a successful config update response.
