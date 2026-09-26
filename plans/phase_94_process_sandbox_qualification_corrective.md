# Phase 94 Plan: Process Sandbox Phase 89 Qualification Corrective

Status: planned (2026-09-26).

Registered in: `plans/roadmap.md`.

Baseline: `bb69e0a43e58cddd0cd047b6a146726b6d12cff6`.

Predecessor: Phase 89 implementation is materially landed, but its terminal
qualification claim is superseded by this phase. Phases 81–84 remain
historically closed with extraction disposition **DEFER**. Phases 92–93 belong
to the independent ICMP qualification line and are not part of this sandbox
corrective.

## Purpose

Close the remaining correctness and qualification gaps found after Phase 89.

The Phase 89 direction remains correct:

- jail startup now has one irreversible guarantee-driven entry;
- generic Landlock no longer unconditionally installs the jail seccomp policy;
- syscall-filter categories are selected from explicit guarantees;
- final seccomp claims are installation-receipt-backed;
- the unsafe `SandboxRequest::intersect()` API is removed;
- the jail request explicitly requires no-network/no-child/no-exec.

Terminal closure was nevertheless premature because:

1. hosted CI on the Phase 89 closeout head is red;
2. Linux `MechanismPlan::filesystem_requested` is computed but ignored at
   entry, so a seccomp-only request still enters Landlock;
3. Linux native seccomp tests still exercise the legacy
   `ProcessSandbox::with_paths(Strict, ...)` path rather than the production
   guarantee-driven entry path.

The Phase 94 invariant is:

> requested mechanisms are the mechanisms that enter, and qualification tests
> exercise the same guarantee-driven path used by production.

This is a narrow correctness/evidence corrective. Do not redesign the portable
guarantee vocabulary or reopen the Phase 84 extraction decision.

## Finding A — hosted proof for Phase 89 is red

GitHub Actions run `36257121876` for the Phase 89 closeout head
`826e634d7b9475c7b0b44badd2f51f07df6ddd17` completed with:

- `dependency-security`: success;
- `ci`: failure;
- failing contract: `cargo xtask verify`;
- failing step: `cargo clippy --profile ci --all-targets -- -D warnings`;
- concrete error: `clippy::collapsible_match` in
  `crates/synvoid-platform/src/sandbox.rs`, in the
  `Guarantee::ExecDenied` receipt-report branch.

The Phase 89 commit message records local `cargo xtask verify 10/10`, but
hosted proof for that exact head is not green.

### Required correction

- Fix the Clippy defect structurally; do not globally suppress the lint.
- Run the full routine contract locally.
- Push all Phase 94 implementation/test/doc changes before claiming closure.
- Observe the GitHub Actions run for the exact implementation SHA.
- Require both `ci` and `dependency-security` to finish successfully on
  that exact SHA.

A rerun of the old failing SHA is not sufficient once code changes.

## Finding B — Linux mechanism selection is still asymmetric

Phase 89 introduced `MechanismPlan` with:

```rust
pub filesystem_requested: bool
```

but `PreparedSandbox::enter()` still creates the platform backend and calls
`backend.apply(...)` unconditionally.

On Linux, a request such as:

```rust
SandboxRequest::new().require(Guarantee::NetworkDenied)
```

therefore still enters Landlock even though the mechanism plan says no
filesystem mechanism was requested.

Phase 89 fixed one direction of coupling (Landlock no longer always installs
seccomp), but the inverse coupling remains (seccomp-only requests still enter
Landlock).

### Required correction

Make the mechanism plan authoritative at entry.

For Linux:

- apply Landlock only when the request selects a filesystem/ambient-resource
  guarantee represented by Landlock;
- install seccomp only when one or more seccomp categories are selected;
- seccomp-only requests must not enter Landlock;
- filesystem-only requests must not install seccomp;
- the combined jail request must enter Landlock once and install one combined
  selected seccomp program once;
- a request selecting neither Linux mechanism must install neither merely
  because a backend object exists.

Do not change legacy `ProcessSandbox` behavior to achieve this. Legacy callers
continue to invoke their backend directly; this correction belongs to the
guarantee-driven `PreparedSandbox::enter()` path.

### Cross-platform constraint

Do not blindly gate every non-Linux backend on the Linux-specific
`filesystem_requested` bit. OpenBSD, macOS, FreeBSD, and Windows may lower
multiple portable guarantees through one native backend.

Acceptable implementations are:

- a Linux-specific conditional in the current entry path, with the asymmetry
  documented and tested; or
- an internal per-backend mechanism/lowering plan that remains private to
  `synvoid-platform`.

Do not leak native mechanism names into the portable public policy API.

## Finding C — final filesystem truth must be installation-backed

Phase 89 made Linux seccomp decisions receipt-backed, but filesystem decisions
still inherit their final status from the pre-entry projection after
`backend.apply()` returns.

Once filesystem entry can be skipped, final reporting must distinguish:

- filesystem mechanism not requested;
- filesystem mechanism requested and installed;
- filesystem mechanism requested but installation failed;
- seccomp category not requested;
- seccomp category requested and installed;
- seccomp category requested but installation failed.

### Required correction

Carry an internal entry receipt/ledger sufficient to express those states.

For Linux finalization:

- a requested filesystem guarantee becomes `Enforced` only after successful
  Landlock entry;
- an unrequested filesystem guarantee remains `NotRequested`;
- a required filesystem install failure returns an error before any
  `EnteredSandbox` is returned;
- seccomp decisions retain category-specific receipt semantics;
- projection alone cannot create a post-entry `Enforced` claim.

This receipt does not need to be public.

## Finding D — native seccomp tests exercise the wrong path

At the Phase 94 baseline,
`crates/synvoid-platform/tests/sandbox_linux_enforcement.rs` routes
`seccomp-socket-denied`, `seccomp-exec-denied`, and
`seccomp-thread-clone-works` through `apply_allowlist()`, which calls:

```rust
ProcessSandbox::with_paths(SandboxLevel::Strict, paths)
```

Phase 89 deliberately removed seccomp installation from that legacy Landlock
path. Those tests therefore no longer qualify the production mechanism:

- socket denial is no longer supplied by the legacy helper;
- exec denial may come from filesystem policy and does not isolate
  `ExecDenied`;
- thread creation can pass even when no seccomp filter was installed.

### Required correction

Split Linux native qualification into two explicit lanes.

### D1. Legacy Landlock/filesystem lane

Keep `ProcessSandbox::with_paths` only for the historical filesystem
contract:

- allowed read succeeds;
- unlisted read fails;
- allowed write succeeds;
- unlisted write fails;
- `no_new_privs` is established;
- impossible explicit-deny policy fails closed.

Add a regression proving filesystem-only legacy entry does not install the
jail network filter. A raw socket operation after legacy Landlock entry should
remain permitted when the host environment otherwise permits it.

Do not use "exec succeeds" as this decoupling proof because Landlock execute
rights can independently deny a new executable.

### D2. Guarantee-driven seccomp lane

Create child probes that enter through:

```rust
let entered = prepare_sandbox(request)?.enter()?;
```

and retain `entered` through the probe.

At minimum qualify:

1. **NetworkDenied**
   - request `NetworkDenied` without filesystem guarantees;
   - raw `socket(AF_INET, SOCK_STREAM, ...)` fails with contracted
     `EPERM`;
   - deterministic entry tests prove Landlock was not selected.

2. **ExecDenied**
   - request `ExecDenied` without filesystem guarantees;
   - raw `execve`/equivalent returns contracted `EPERM`;
   - arbitrary filesystem-denied errno is not accepted as seccomp proof.

3. **ChildCreationDenied**
   - request `ChildCreationDenied` without unrelated syscall categories;
   - directly exercise process creation (`fork`, non-thread `clone`, or a
     Linux-equivalent probe that isolates this category);
   - assert contracted denial;
   - separately prove thread creation remains usable.

4. **Category isolation**
   - network-only selection does not acquire child/exec categories;
   - child-only selection does not acquire network/exec categories;
   - exec-only selection does not acquire network/child categories;
   - deterministic mechanism-plan/receipt tests may prove the negative
     selection half; native probes prove each positive enforcement family.

5. **Combined jail policy**
   - `jail_guarantee_request()` selects filesystem + network + child + exec;
   - one `PreparedSandbox::enter()` installs each selected mechanism once;
   - real WASM/YARA jail round trips still work under the combined policy.

## Finding E — unsupported hosts must not become native proof

The Linux suite currently permits an explicit unsupported path when Landlock
is unavailable. That is useful for portability, but a green test process that
returns early is not enforcement evidence.

Phase 94 evidence must distinguish:

- **enforced/pass** on a host that actually exercised the selected mechanism;
- **unsupported/unqualified** where the host cannot exercise it;
- **failure** where the mechanism was expected to work but did not.

If the routine GitHub runner lacks Landlock, record that explicitly and use a
known-capable Linux host for native enforcement evidence. Hosted CI must still
be green for compilation/lint/unit/guard contracts.

Do not redesign routine CI into a broad privileged matrix.

## Workstream F — deterministic entry/receipt tests

Expand the fake/counting entry seam so it proves actual entry selection rather
than only projection.

Required cases:

| Request | Linux filesystem apply | Seccomp install |
|---|---:|---|
| filesystem-only | 1 | 0 |
| NetworkDenied only | 0 | 1 network |
| ChildCreationDenied only | 0 | 1 child |
| ExecDenied only | 0 | 1 exec |
| network + exec | 0 | 1 combined network+exec |
| jail request | 1 | 1 combined network+child+exec |

Also prove:

- filesystem install failure => error, no witness;
- seccomp install failure => error, no witness;
- skipped/unrequested mechanisms cannot appear `Enforced`;
- each selected mechanism is entered at most once;
- stale receipts cannot be reused across entry attempts;
- the retained witness still owns lifetime-significant native state.

Prefer behavioral counting/receipt tests over source-text checks alone. Retain
the existing jail source guard preventing reintroduction of the legacy second
entry.

## Workstream G — documentation and evidence reconciliation

Update only current binding material affected by this corrective:

- `docs/SANDBOXING.md`;
- `architecture/process_sandbox_corrective_closeout.md` with a Phase 94
  addendum;
- `architecture/sandbox_jail_protocol.md` if it names the stale Linux test
  path;
- `.opencode/skills/sandboxing/SKILL.md`;
- `plans/phase_89_process_sandbox_entry_and_policy_semantics_corrective.md`;
- `plans/roadmap.md`;
- this plan.

Required truth after closure:

- Phase 89 implementation remains historical evidence, but its original
  terminal hosted-proof claim is superseded;
- Phase 94 is the proof-bearing corrective;
- legacy Landlock tests prove filesystem semantics only;
- guarantee-driven tests prove seccomp semantics;
- Linux entry honors the selected mechanism plan;
- exact proof-bearing SHA and hosted run id are recorded;
- extraction remains **DEFER**.

Do not rewrite Phases 81–84 as if they originally contained Phase 94 behavior.

## Verification

Before closure run at least:

    cargo fmt --all -- --check
    cargo clippy --profile ci --all-targets -- -D warnings
    cargo test -p synvoid-platform --profile ci
    cargo test -p synvoid-jail-runtime --profile ci
    cargo test --test jail_isolation_guard --profile ci
    cargo xtask test guards
    cargo xtask verify
    cargo deny check
    cargo audit

On a Landlock-capable Linux host also run the corrected native sandbox suite
and real jail integration lane.

If a dedicated native sandbox qualification command is introduced, it must:

- run irreversible probes in child processes;
- report unsupported separately from pass;
- emit bounded machine-readable evidence;
- avoid root where Landlock/seccomp do not require it;
- remain additive to, not a substitute for, `cargo xtask verify`.

## Hosted proof gate

After all corrections are committed:

1. push the implementation SHA;
2. observe GitHub Actions for that exact SHA;
3. require `ci == success`;
4. require `dependency-security == success`;
5. record the run id and SHA in this plan and the closeout addendum;
6. only then mark Phase 94 closed and restore the roadmap statement that no
   process-sandbox corrective remains executable.

Local green verification is necessary but not sufficient.

## Acceptance criteria

Phase 94 is complete only when:

- the hosted Clippy failure from run `36257121876` is corrected;
- Linux mechanism selection at entry is operative, not informational;
- seccomp-only guarantee requests do not enter Landlock;
- filesystem-only requests do not install seccomp;
- combined jail entry installs filesystem confinement once and selected
  seccomp categories once;
- final filesystem and seccomp decisions are backed by successful entry
  receipts;
- legacy Linux qualification is limited to filesystem semantics;
- native seccomp probes enter through `prepare_sandbox(...).enter()`;
- NetworkDenied is proven with the contracted errno;
- ExecDenied is proven independently of Landlock path denial;
- ChildCreationDenied and thread preservation are directly qualified;
- category-isolation tests prevent unrelated syscall-family selection;
- real jail WASM/YARA workload tests remain green under the combined policy;
- unsupported Linux hosts are recorded as unqualified, not enforcement proof;
- `cargo xtask verify`, `cargo deny check`, and `cargo audit` are green;
- hosted `ci` and `dependency-security` are green on the exact
  proof-bearing SHA;
- docs/evidence are reconciled;
- extraction remains **DEFER**.

## Rejection criteria

Reject an implementation that:

- deletes `filesystem_requested` while retaining unconditional Landlock entry;
- installs every Linux mechanism for every request;
- moves seccomp back into `LandlockSandbox::apply()`;
- changes legacy `SandboxLevel::Basic/Strict` semantics to make tests pass;
- keeps seccomp test names while exercising only the legacy adapter;
- accepts filesystem denial as proof of `ExecDenied`;
- counts unsupported-host early return as native enforcement proof;
- suppresses the Clippy warning globally;
- closes from local verification while hosted CI is red or unobserved;
- reopens extraction/publication.

## Terminal state

This is one bounded implementation/qualification corrective.

If all acceptance criteria pass:

- mark Phase 94 closed with implementation/proof SHA and hosted run id;
- add the Phase 94 supersession note to the sandbox closeout;
- restore the roadmap terminal statement that no process-sandbox corrective
  remains executable;
- leave Phases 81–84 **DEFER** and Phase 89 as historical implementation
  evidence;
- do not register an extraction phase merely because Phase 94 closes.

If native Linux enforcement cannot be obtained, implementation may land but
Phase 94 must remain qualification-open with the missing evidence recorded.
