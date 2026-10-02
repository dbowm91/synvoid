# Phase 120 Plan: Sandbox Guarantee-Boundary Internal Crate Split Decision

Status: **CLOSED RETAIN** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

Historical disposition: Phases 81–94 DEFER external extraction. That disposition
remains authoritative for publication/repository support. This phase evaluates
only whether a narrower internal crate improves auditability and standalone
package readiness while staying in the monorepo.

## Goal

Determine whether the portable sandbox guarantee model and native enforcement
backends can be cleanly separated from the broad `synvoid-platform` crate into
an internal `synvoid-sandbox` crate.

The split is justified only if it reduces unrelated platform dependency
reachability and preserves the existing fail-closed guarantee/evidence model.

## Ecosystem context

Birdcage is archived. Skarn and Zerobox provide active native-sandbox
implementations with different mechanism/support choices. SynVoid's distinct
contract is not raw backend availability; it is:

- caller-selected Required/Optional guarantees;
- prepare then irreversible enter;
- `EnforcementReport` / retained `EnteredSandbox` evidence;
- preopened/inherited resource intent;
- explicit unsupported/fail-closed outcomes;
- jail descendant/owner lifecycle semantics.

Do not expand scope into an agent sandbox product or copy competitors' CLI/policy
surfaces.

## Workstream A — split feasibility inventory

Map every item in `crates/synvoid-platform/src/sandbox.rs` and its private
backend helpers.

Classify dependencies into:

- sandbox policy/value vocabulary;
- mechanism planning;
- native backend implementation;
- generic platform detection;
- generic filesystem/path helper;
- process/job control shared with non-sandbox platform functions;
- Wintun/service/socket unrelated capability.

Target dependency direction if feasible:

```text
synvoid-platform  -> synvoid-sandbox   # only if platform facade re-exports
synvoid-jail-runtime -> synvoid-sandbox
root adapters -> synvoid-sandbox
synvoid-sandbox -> std + narrow native deps
synvoid-sandbox -X-> synvoid-platform
```

Prefer no dependency from the new crate back to broad `synvoid-platform`.
Move the minimal platform enum/helper locally or into an already-neutral leaf if
needed; do not create a cycle.

## Workstream B — preserve guarantee semantics byte/behavior exactly

Move without semantic redesign first:

- `Guarantee`;
- `SandboxRequest`;
- `SandboxCapabilities`;
- `MechanismPlan`;
- `EnforcementReport`;
- `PreparedSandbox`;
- `EnteredSandbox`;
- `PreopenedResource`;
- backend contract and errors.

Compatibility re-exports may remain in `synvoid-platform::sandbox` during the
transition.

Pin tests before movement so required/optional decisions and receipt contents are
identical.

## Workstream C — backend ownership

Move only backend code needed to implement the guarantee contract.

Keep unrelated platform operations (socket FD passing, service management,
daemonization, Wintun, generic path APIs) in `synvoid-platform`.

Linux Landlock/seccomp dependencies should become sandbox-owned target
dependencies if the split occurs. BSD/macOS/Windows dependencies move only where
sandbox-specific.

Do not upgrade support tiers:
- Linux strict/native claims remain evidence-backed;
- macOS Seatbelt remains experimental/deprecated mechanism;
- Windows Job Objects remain process/resource containment, not filesystem access
  isolation;
- BSD support remains exactly as documented.

## Workstream D — native evidence and consumers

Re-run existing native child-process tests using the canonical new API.

The production consumer remains `synvoid-jail-runtime`; root upload/test helpers
do not become a fictional second independent consumer.

An outside-workspace package test may be added to prove no hidden SynVoid runtime
requirement, but the crate remains class 2/internal and external extraction DEFER.

## Workstream E — GO/RETAIN decision

GO_INTERNAL_SPLIT requires:

- no dependency cycle;
- broad platform crate loses sandbox-specific native dependencies/surface;
- jail runtime consumes the new canonical crate directly;
- compatibility facade is thin;
- native evidence remains truthful;
- package tarball builds outside workspace.

Otherwise RETAIN `synvoid-platform::sandbox` and document why the split would
increase complexity.

## Verification

Minimum:

```bash
cargo test -p synvoid-platform --profile ci
cargo test -p synvoid-jail-runtime --profile ci
cargo test -p synvoid-jail-protocol --profile ci
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
```

If a new crate is created, add its package/dry-run/outside-workspace test and all
existing native sandbox workflow lanes. Cross-compile results must not be recorded
as native enforcement proof.

## Acceptance criteria

- explicit GO_INTERNAL_SPLIT or RETAIN decision;
- zero semantic weakening in Required/Optional/fail-closed behavior;
- platform support matrix remains truthful;
- no external repository/public-support promise;
- dependency reachability improves if and only if a split lands.

## Rejection criteria

Reject implementation that:

- treats Job Objects as equivalent to AppContainer;
- converts macOS Seatbelt into a supported claim without evidence;
- broadens seccomp/Landlock policy while moving files;
- introduces a cycle back to `synvoid-platform`;
- removes enforcement receipts or retained entry witnesses;
- calls the crate standalone/public merely because it packages.

## Formal closeout

Disposition: **RETAIN** `synvoid-platform::sandbox`; no files or runtime APIs
were moved. The guarantee contract and platform-specific backend code currently
share `crates/synvoid-platform/src/sandbox.rs` and its `crate::sandbox::{linux,
capsicum,pledge,windows,darwin}` implementations. The production consumer
`synvoid-jail-runtime::sandbox_entry` uses the canonical prepare/enter API from
`synvoid-platform`, and existing conformance tests inspect those canonical
symbols and backend implementation structure. The broad platform crate's
target-scoped dependencies also support non-sandbox operations (notably socket,
process, service and Wintun facilities), so no dependency-reachability reduction
was demonstrated by this source-only split decision.

An internal crate could own the API, but doing so now would duplicate or relocate
a large multi-platform enforcement surface and require rebuilding native CI
coverage without a demonstrated reduction in unrelated dependencies. Retaining
the current canonical boundary is lower risk. The support matrix and external
DEFER remain unchanged. Evidence and verification are recorded in
`architecture/standalone_crate_phase120_closeout.md`.
