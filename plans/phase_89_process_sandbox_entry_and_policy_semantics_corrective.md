# Phase 89 Plan: Process Sandbox Entry and Policy Semantics Corrective

Status: closed (2026-09-26).

Registered in: `plans/roadmap.md`.

Baseline: `7462bb9f36983aaffa8c8d9ec14595240557c3c7`.

Predecessor/closeout: Phases 81–84 are closed **DEFER** in
`architecture/process_sandbox_corrective_closeout.md`. This phase is a
post-closeout correctness follow-up. It does **not** reopen the extraction
decision or authorize a standalone crate/repository.

## Purpose

Correct four bounded semantic defects found during post-closeout review:

1. the jail currently performs two irreversible sandbox entries;
2. the generic Linux Landlock backend installs the jail-specific seccomp
   filter even when the caller did not request syscall restrictions;
3. `SandboxRequest::intersect()` weakens required guarantees and does not
   actually intersect resource/path authority;
4. the jail guarantee request does not yet state the network/child/exec
   guarantees that the Phase 83 Linux mechanism now enforces.

The target invariant is:

> one irreversible entry per workload, and only mechanisms selected by the
> explicit guarantee request.

This is a semantics/correctness corrective, not a new sandbox architecture.

## Finding A — jail entry is currently irreversible twice

At the Phase 89 baseline,
`crates/synvoid-jail-runtime/src/sandbox_entry.rs::apply_jail_sandbox()`
first executes:

```rust
ProcessSandbox::with_paths(SandboxLevel::Strict, legacy_paths).is_ok()
```

and then separately executes:

```rust
prepare_sandbox(request)?.enter()
```

The first call is not a compatibility probe. On enforcing platforms it applies
the legacy sandbox irreversibly. The second call then applies the new
guarantee-driven sandbox again.

Consequences:

- Linux stacks two Landlock domains and currently installs the seccomp filter
  twice;
- OpenBSD can lock `unveil`/apply `pledge` before the second entry tries
  to construct its policy;
- the Phase 82 lifecycle statement that `PreparedSandbox::enter()` is the
  single irreversible transition is false for the jail;
- `legacy_ok` logging is derived from a side effect rather than a pure
  compatibility decision.

### Required correction

- Production jail startup must call exactly one irreversible sandbox-entry
  path.
- Remove the production `ProcessSandbox::with_paths(Strict, ...)` call from
  `apply_jail_sandbox`.
- If a legacy-compatibility diagnostic is still useful, compute it from a pure
  capability/projection helper or keep it test-only. Do not enter the legacy
  sandbox to answer a boolean.
- Retain the resulting `EnteredSandbox` through the framed serve loop exactly
  as Phase 81 intended.
- Keep the test-only no-sandbox hatch explicit and production-inaccessible.

### Required regressions

Add at least one deterministic fake/backend-injection test proving one
prepared request produces one backend entry. Also add a source/repo guard or
equivalent focused regression preventing a production
`ProcessSandbox::with_paths(SandboxLevel::Strict, ...)` call from returning
to the jail entry path.

Do not prove this by actually stacking irreversible host sandboxes inside the
test process.

## Finding B — generic Landlock is coupled to the jail seccomp policy

At the baseline, `LandlockSandbox::apply()` always calls
`seccomp::apply_jail_filter()`.

This makes the legacy/generic backend behavior stronger than its public
contract:

- `SandboxLevel::Basic` on Linux unexpectedly denies new sockets, child
  process creation, and exec;
- legacy `SandboxCapabilities` still reports network/child restrictions as
  false;
- `docs/SANDBOXING.md` says Basic Landlock has no
  network/process/child restrictions;
- callers using `ProcessSandbox::with_paths` receive jail-specific behavior
  they did not request.

The seccomp filter is useful, but it belongs to the guarantee-driven mechanism
selection, not to every invocation of Landlock.

### Required correction

Split Linux filesystem confinement from syscall-filter confinement.

The expected shape is:

1. Landlock entry enforces only filesystem/ambient-resource guarantees.
2. The guarantee-driven prepared plan determines whether a syscall-filter
   mechanism is required.
3. `PreparedSandbox::enter()` applies each selected mechanism once.
4. The final `EnforcementReport` is derived from mechanisms that actually
   installed successfully, not merely from a compile-time filter probe.

The exact internal types are implementation-defined, but prefer a narrow
internal mechanism plan/receipt such as:

- filesystem Landlock requested/applied;
- network-denial seccomp requested/applied;
- child-creation-denial seccomp requested/applied;
- exec-denial seccomp requested/applied;
- backend-owned lifetime state.

Do not expose Linux-specific mechanism details in the portable public policy
surface.

### Syscall-filter selection semantics

The filter compiler must be driven by requested guarantees.

At minimum:

- `NetworkDenied` selects the network-denial rules needed for the documented
  guarantee;
- `ChildCreationDenied` selects fork/vfork/non-thread-clone/clone3 denial;
- `ExecDenied` selects execve/execveat denial;
- if none of those guarantees is requested, no jail seccomp filter is
  installed;
- a request for only one category must not silently acquire unrelated
  restrictions unless that stronger behavior is explicitly documented and
  accepted by the portable contract.

`NetworkTcpRestricted` / `NetworkUdpRestricted` must not be reported as
independently enforced unless the installed filter actually distinguishes the
requested protocol semantics. If the implementation cannot do so without
broader denial, report the narrower guarantee unsupported rather than silently
overrestricting a generic caller.

Keep the existing design constraints:

- pure Rust `seccompiler`;
- no new system `libseccomp` dependency;
- deterministic errno behavior;
- thread creation required by Wasmtime/YARA remains functional;
- TSYNC/all-thread install where the guarantee requires it;
- no giant syscall allowlist.

### Legacy compatibility

After this correction:

- legacy `ProcessSandbox`/Landlock Basic and Strict keep their historical
  filesystem semantics;
- legacy `SandboxCapabilities` remain truthful for that path;
- new production security decisions use the guarantee contract;
- jail-specific syscall restrictions come only through the guarantee request.

Do not reinterpret old config strings merely because the new guarantee path is
stronger.

## Finding C — `SandboxRequest::intersect()` is unsafe/misnamed policy algebra

The current method:

- intersects the two `required` guarantee sets, so disjoint requirements are
  silently discarded;
- concatenates optional guarantees without a complete authority model;
- copies paths, scope, and resources only from `self`;
- therefore does not represent a security-policy intersection or a guaranteed
  tightening operation.

The current conformance test blesses this weakening by asserting that
requirements present on only one side disappear.

At this baseline no production call site requires generic request composition;
the method is exercised only by conformance tests.

### Required correction

Preferred outcome: **remove `SandboxRequest::intersect()` for now rather
than publish incorrect policy algebra inside the workspace.**

- Delete/replace the conformance test that treats dropping required guarantees
  as "narrowing".
- Keep request construction explicit at call sites.
- Do not invent a generalized path/resource lattice solely to preserve this
  method.

If implementation discovers a real production caller that genuinely requires
composition, replace the method with an explicitly named fallible tightening
operation (for example `tighten_with`) and prove these laws:

1. required guarantees are monotonic: composition contains the union of both
   required sets;
2. an optional guarantee cannot override a required guarantee;
3. deny authority only grows;
4. allow authority only shrinks;
5. resource authority only shrinks;
6. incompatible/incomparable thread scopes return a typed error rather than
   choosing one silently;
7. path/resource composition rejects ambiguous cases rather than guessing;
8. `A.tighten_with(B)` can never authorize an operation forbidden by A or B.

Any replacement needs table/property tests for commutativity where applicable,
idempotence, and monotonic non-broadening. If no real caller exists, removal
is the safer implementation and satisfies this phase.

## Finding D — the jail request lags the Phase 83 security boundary

`jail_guarantee_request()` currently requires:

- `AmbientFilesystemDenied`;
- `FilesystemReadAllowlist`;
- `InheritedIpcUsable`;
- `DescendantsConfined`.

Phase 83 then installs Linux seccomp rules for no-network/no-child/no-exec
unconditionally. The code therefore enforces properties that the portable jail
contract does not require.

The Phase 82/83 design text already states that jail modules/rules arrive via
inherited IPC and should need no new network authority, child processes, or
new exec.

### Required correction

After guarantee-driven seccomp selection exists, make the jail request itself
authoritative.

Unless workload qualification proves one of these is genuinely necessary,
require:

- `NetworkDenied`;
- `ChildCreationDenied`;
- `ExecDenied`.

Then let support truth fall out of the backend matrix:

- Linux must install and prove the corresponding seccomp clauses;
- OpenBSD may satisfy them through pledge/unveil where native evidence exists;
- macOS must fail `Required` if exec denial remains unproven;
- Windows remains fail-closed for access-control guarantees;
- test-only hatch behavior remains explicit and unchanged.

Do not weaken the jail requirement merely to preserve a platform support label.
If native Wasmtime/YARA qualification demonstrates that a guarantee cannot be
required on a supported platform, document the actual workload dependency and
make the smallest justified exception in the request/report model.

## Finding E — preparation/final reporting must distinguish projection from installation

The current guarantee implementation projects backend support before entry and
then reconstructs the final report from the same backend projection after
entry.

Once mechanism selection becomes request-driven, a compile/probe result is not
sufficient evidence that a mechanism was installed.

### Required correction

- Keep preparation side-effect-free.
- Use available side-effect-free runtime probes to reject clearly unavailable
  required mechanisms early.
- Carry the selected mechanism plan into `enter`.
- Have entry produce an internal application receipt/result describing what
  actually installed.
- Build the final `EnforcementReport` from that receipt.
- A required guarantee whose install fails or returns partial/unverified state
  must return an error and must never appear as `Enforced` in an
  `EnteredSandbox`.

This does not require a public status-enum redesign if the existing projection
API can remain clearly documented as projected support. It does require the
post-entry report to be installation-backed.

## Workstream F — documentation and capability reconciliation

Update current binding docs after runtime corrections:

- `docs/SANDBOXING.md`;
- `architecture/platform.md`;
- `architecture/sandbox_jail_protocol.md`;
- `.opencode/skills/sandboxing/SKILL.md`;
- `architecture/process_sandbox_corrective_closeout.md` with a Phase 89
  addendum/supersession note;
- `plans/roadmap.md` and this plan status/evidence.

Required truth after correction:

- legacy Linux Basic/Strict path policy does not imply jail seccomp;
- guarantee-driven Linux requests state exactly which seccomp categories are
  installed;
- the jail request lists every required security property explicitly;
- one irreversible jail entry is the documented lifecycle;
- no docs present `SandboxRequest::intersect()` as safe composition if it is
  removed;
- DEFER extraction disposition remains unchanged unless separate future
  evidence triggers re-evaluation.

## Verification

Run at least:

    cargo fmt --all -- --check
    cargo test -p synvoid-platform --profile ci
    cargo test -p synvoid-jail-runtime --profile ci
    cargo test --test jail_isolation_guard --profile ci
    cargo xtask test guards
    cargo xtask verify
    cargo deny check
    cargo audit

Add focused tests for:

- exactly one irreversible/backend entry per jail startup;
- legacy Linux Basic/Strict filesystem behavior does not install the
  jail-specific seccomp filter;
- guarantee request with no syscall guarantees installs no seccomp filter;
- NetworkDenied selects only the justified network mechanism;
- ChildCreationDenied selects the process-creation mechanism;
- ExecDenied selects the exec mechanism;
- combined jail request installs all required clauses once;
- seccomp installation failure causes `PreparedSandbox::enter()` to fail
  closed with no `EnteredSandbox`;
- final report comes from successful installation receipts;
- the jail required set contains network/child/exec guarantees after workload
  qualification;
- policy-composition API is either removed or proven monotonic/non-broadening;
- legacy adapter tests remain green without using legacy entry in production
  jail startup.

On Linux, run the native child enforcement suite and real WASM/YARA jail
round trips under the guarantee-driven filter. Cross-compilation alone remains
insufficient enforcement evidence.

Where macOS/OpenBSD/Windows semantics are affected by the stricter jail
required set, run the corresponding native qualification lane or retain the
backend's lower support tier/fail-closed result truthfully.

## Acceptance criteria

Phase 89 is complete only when:

- jail startup has exactly one irreversible sandbox-entry transition;
- no production compatibility boolean enters a sandbox as a side effect;
- `LandlockSandbox::apply()` no longer unconditionally installs the
  jail-specific seccomp filter;
- generic/legacy Linux Basic behavior matches its documented capability
  surface;
- seccomp categories are selected from explicit guarantees;
- no syscall-filter guarantee is reported enforced solely because its program
  compiled;
- final guarantee reports reflect successful installation receipts;
- the jail request explicitly requires its no-network/no-child/no-exec
  boundary unless workload evidence records a narrower justified contract;
- `SandboxRequest::intersect()` is removed, or a replacement is formally
  tightening and regression-tested;
- no required guarantee can disappear during composition;
- jail fail-closed, restart, IPC, and witness-retention behavior remain intact;
- Phases 81–84 extraction disposition remains DEFER;
- current docs and runtime agree.

## Rejection criteria

Reject implementation that:

- keeps both legacy entry and guarantee entry and merely suppresses one log;
- leaves seccomp inside every Landlock apply and changes docs to pretend that
  was always Basic behavior;
- reports projected/compiled seccomp as installed enforcement;
- preserves `intersect()` by renaming it without fixing its authority
  semantics;
- weakens jail requirements solely to retain macOS/Windows support labels;
- adds a generic command-runner/process-supervisor API;
- introduces a system libseccomp dependency without a separate measured
  decision;
- changes unrelated sandbox extraction/publication status.

## Terminal state

This is one bounded corrective phase.

Closure record (2026-09-26):

- Implementation: single-entry jail startup (legacy probe deleted + source
  guard), Landlock/seccomp decoupling with guarantee-selected categories and
  receipt-backed reports, `intersect()` removal with explicit-composition
  tests, authoritative jail network/child/exec requirements, docs
  reconciliation (`docs/SANDBOXING.md`, `architecture/platform.md`,
  `architecture/sandbox_jail_protocol.md`, sandboxing skill, this plan).
- Verification: `cargo test -p synvoid-platform --profile ci` green
  (conformance 18/18, no-downgrade 12/12, lib 19/19 incl. 4 new mechanism
  tests), `cargo test -p synvoid-jail-runtime --profile ci` green (4/4 incl.
  single-entry guard + updated jail boundary),
  `cargo test --test jail_isolation_guard --profile ci` green, Linux
  target check clean, `cargo xtask test guards` green.
- Addendum: `architecture/process_sandbox_corrective_closeout.md` §11
  documents the superseded double-entry/seccomp-coupling/composition
  semantics.
- Phases 81–84 **DEFER** extraction decision still in force.

A new extraction plan must not be registered merely because Phase 89 closes.
Only the re-evaluation triggers already recorded by Phase 84 can reopen that
decision.
