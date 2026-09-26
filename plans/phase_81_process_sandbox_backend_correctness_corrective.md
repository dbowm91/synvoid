# Phase 81 Plan: Process Sandbox Native Backend Correctness Corrective

Status: planned (2026-09-26).

Roadmap: `plans/process_sandbox_corrective_extraction_readiness_roadmap.md`.

Baseline: `81638c251592913579bd9bbce51d013c44d67910`.

Primary goal: repair the concrete Linux Landlock and Windows Job Object / mitigation ABI defects before changing the portable sandbox API. This phase is intentionally backend-correctness-first.

## Scope

Canonical implementation remains `crates/synvoid-platform/src/sandbox.rs`. Root `src/platform/` remains a pure compatibility facade. Jail entry remains in `crates/synvoid-jail-runtime/src/sandbox_entry.rs`.

Do not implement AppContainer, a new cross-platform policy type, or a standalone crate in this phase.

## Workstream A — Freeze current call-site behavior

Inventory every production call to `ProcessSandbox::new`, `with_paths`, `capabilities`, and `is_supported`.

Record:

- caller;
- whether the returned `ProcessSandbox` is retained or immediately dropped;
- requested level and paths;
- whether the caller runs before or after threads/resources are created;
- whether failure is fail-open or fail-closed;
- which claims are security-critical.

At minimum cover worker startup, WASM/YARA jail startup, upload scanning helpers, tests, and config/operator documentation.

Add a focused static/behavioral regression that prevents a successful `IsolationPolicy::Required` jail from entering its request loop after sandbox installation failure.

## Workstream B — Replace or repair raw Landlock construction

Preferred implementation: add target-Linux dependency on the maintained `landlock` crate and delete the handwritten Landlock UAPI structures/constants that it replaces.

Before adopting it, record:

- dependency count/features;
- default and minimal release binary-size delta;
- supported architectures relevant to SynVoid;
- minimum Rust compatibility against the workspace toolchain;
- whether the needed API is available without optional features.

Use explicit compatibility levels:

- minimum restrictions that back a required SynVoid guarantee use `CompatLevel::HardRequirement`;
- opportunistic newer rights may use best effort only if the enforcement report says they are optional;
- production must inspect restriction status and must not translate `PartiallyEnforced` / `NotEnforced` into full enforcement.

For the current filesystem behavior:

- handle all filesystem rights required to make the allowlist semantics truthful for the running supported ABI;
- add read rules for read roots and read+write rules for write roots;
- do not claim explicit deny-path support on Landlock when a requested deny overlaps an allowed ancestor and cannot be represented;
- stop using kernel release text as a security gate; use the Landlock ABI/capability result.

Enforcement must establish `no_new_privs`. Where the crate/runtime supports atomic `restrict_self` no-new-privs semantics, use it; otherwise use the documented `PR_SET_NO_NEW_PRIVS` sequence and verify it.

If the `landlock` crate is rejected by the measured dependency/footprint gate, retain raw syscalls only if all of the following are implemented and tested:

- version query uses null attr + zero size + `LANDLOCK_CREATE_RULESET_VERSION`;
- production ruleset creation uses flags 0 with a valid ABI-sized structure;
- supported access masks are derived from the probed ABI;
- `no_new_privs` is established before enforcement on ABIs that need it;
- thread/process scope is explicitly recorded;
- error paths close every ruleset/path fd.

## Workstream C — Native Linux enforcement tests

Add a dedicated child-process integration target; never Landlock the test runner.

Required cases:

1. backend probe reports the actual Landlock status;
2. allowed read succeeds;
3. denied/unlisted read fails;
4. allowed write succeeds;
5. unlisted write/create fails;
6. `PR_GET_NO_NEW_PRIVS` (or equivalent backend status) proves no-new-privs after entry;
7. an intentionally impossible hard requirement fails before the child enters workload code;
8. an unsupported/disabled Landlock host reports unsupported rather than passing or skipping as success.

The Linux CI host should run the enforcement test when its kernel advertises the required ABI. If the CI environment lacks Landlock, emit an explicit unsupported result and retain a native qualification lane/host whose successful enforcement is release evidence. A "skip because sandbox failed" is not proof.

## Workstream D — Correct Windows Job Object ABI use

Delete local ABI redefinitions wherever `windows-sys` exposes the canonical structure, enum, or constant.

Use the generated equivalents for:

- extended Job Object limit information;
- `JobObjectExtendedLimitInformation`;
- `JOB_OBJECT_LIMIT_PROCESS_MEMORY`;
- `JOB_OBJECT_LIMIT_JOB_MEMORY`;
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`;
- any process-count limit if later configured.

Preserve the existing 256 MiB per-process and 512 MiB per-job defaults in this corrective unless a separate config decision changes them.

After `SetInformationJobObject`, query the object back with `QueryInformationJobObject` and verify the effective flags/limits in native tests.

Handle nested-job behavior explicitly. If `AssignProcessToJobObject` fails because the process is already constrained by an incompatible outer job, return a typed unsupported/conflict result; do not report limits as installed.

## Workstream E — Correct mitigation policy ABI use

Use the real `PROCESS_MITIGATION_DEP_POLICY`, `PROCESS_MITIGATION_ASLR_POLICY`, or the exact generated equivalents expected by `SetProcessMitigationPolicy`.

Do not pass `PROCESS_CREATION_MITIGATION_POLICY_*` scalar constants to `SetProcessMitigationPolicy`.

Native tests should query the effective process mitigation policy after installation where the API permits it.

A mitigation that is already mandatory/default on a modern Windows host may report "already enforced"; it must not be reported as newly applied if the setter failed.

## Workstream F — Remove host-global DACL mutation from sandbox semantics

`apply_file_restrictions` changes ACLs on filesystem objects themselves. It is not a process-scoped allowlist and can affect other processes/users.

Remove it from `WindowsSandbox::apply` and from all capability claims.

If another SynVoid subsystem legitimately needs durable ACL hardening, move that behavior to an explicitly named filesystem-hardening API with separate ownership and tests. Do not retain it merely for parity with old Strict code.

Windows `Strict` remains fail-closed for filesystem/access-control isolation after this phase.

## Workstream G — Own lifetime-sensitive Windows handles

Do not convert the leaked Job Object handle into a short-lived RAII local and then drop it after assignment: with kill-on-close, closing the last job handle can terminate associated processes.

Introduce the minimum internal owned state needed to keep the job handle alive for the intended confinement lifetime. Phase 82 will generalize this as `EnteredSandbox`; Phase 81 may use a backend-specific guard/state object provided its lifetime cannot be accidentally discarded by current call sites.

Audit `apply_jail_sandbox`: it currently drops the returned `ProcessSandbox` before the serve loop. Either retain a backend state guard through the loop in this phase or structure the correction so no security-significant state is dropped. Do not leak raw handles as the permanent solution.

## Workstream H — Documentation truth correction

After runtime fixes land, update current binding docs to say exactly what was proven:

- `docs/SANDBOXING.md`;
- `architecture/platform.md`;
- `architecture/sandbox_jail_protocol.md` where its Linux denial matrix depends on Landlock;
- `.opencode/skills/sandboxing/SKILL.md`.

Historical Phase 46/48 files remain historical. Add a forward/supersession note only where current readers could otherwise treat the old Linux/Windows evidence as current terminal proof.

Do not claim Linux production strict enforcement until the new native test has passed.

## Verification

At minimum:

    cargo fmt --all -- --check
    cargo test -p synvoid-platform --profile ci
    cargo test -p synvoid-jail-runtime --profile ci
    cargo test --test jail_isolation_guard --profile ci
    cargo xtask test guards
    cargo xtask verify
    cargo deny check
    cargo audit

Plus native Windows and Linux sandbox-enforcement tests added by this phase and cross-target checks for supported Windows/Linux targets.

## Acceptance criteria

- no production Landlock ruleset is created with VERSION/ERRATA query flags;
- `no_new_privs` is verified for unprivileged Landlock enforcement;
- required Landlock restrictions cannot be partially/not enforced and still return success;
- native Linux child tests demonstrate actual filesystem denial;
- Windows uses generated Job Object ABI definitions and class 9 extended-limit information;
- native Windows tests query back the intended memory and kill-on-close flags;
- mitigation setters receive the documented structures;
- sandbox application performs no host-global filesystem ACL mutation;
- security-significant Windows handles have explicit ownership and lifetime;
- existing jail IPC/protocol semantics and default configuration are unchanged;
- docs no longer cite Phase 46 as sufficient evidence for the corrected backends.

## Rejection criteria

Reject implementation that:

- only changes constants without adding native behavioral/query evidence;
- keeps a best-effort Landlock result on a required path;
- fixes the Job Object handle leak by closing the last handle while the confined process is running;
- introduces AppContainer in the same corrective;
- changes configured memory limits or sandbox level semantics incidentally;
- leaves DACL mutation behind under a different sandbox method name.
