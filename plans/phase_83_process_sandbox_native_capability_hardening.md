# Phase 83 Plan: Process Sandbox Native Capability Hardening

Status: closed 2026-09-26 as **HARDENED** (seccomp adopted + qualified by
construction and child tests; Capsicum/OpenBSD hardened; Seatbelt mapped;
Windows launch gate explicitly retained as future work, never weakened).
Implementation SHA: `96bc53e119ed079e121db2ed6497dfd2c3b2b011` (same commit as Phase 81).
See `architecture/process_sandbox_corrective_closeout.md` (§5, §7).

Roadmap: `plans/process_sandbox_corrective_extraction_readiness_roadmap.md`.

Depends on: Phases 81-82.

Primary goal: lower the new guarantee contract onto stronger native mechanisms where SynVoid has a real use case, without pretending all platforms implement the same primitive.

## Workstream A — Linux Landlock scope

Keep Landlock responsible for ambient filesystem access and only those network guarantees that are both supported by the running ABI and deliberately requested.

Do not make the policy depend on a numeric kernel version. Use backend compatibility/status.

Landlock network support is versioned: TCP restrictions begin at ABI 4; UDP restrictions are later (ABI 10 in current kernel UAPI, newer than the Rust `landlock` crate's current ABI-9 surface at planning time). Therefore a portable `NetworkDenied` guarantee must not be declared solely from Landlock unless all socket classes required by that guarantee are actually covered.

Do not wait for a future Landlock crate release to close this campaign if a separate syscall-filter layer can prove the jail's narrower network-denial requirement.

## Workstream B — Linux seccomp layer

Qualify `seccompiler` as the preferred pure-Rust syscall-filter mechanism.

Scope the first filter to categorical denial needed by the jail, not a full syscall allowlist:

- deny creation/use of network sockets needed to obtain new network authority;
- deny `fork`, `vfork`, `clone`, `clone3` as necessary for child creation;
- deny `execve` and `execveat`;
- preserve inherited stdin/stdout/stderr pipe operation;
- preserve Wasmtime/YARA runtime syscalls demonstrated by real workload tests.

Choose deterministic denial behavior (for example errno versus kill) and make it part of the internal contract/tests. Security-sensitive bypass must not be configurable from untrusted input.

Install the filter after all required startup resources are created and before any untrusted module/rule work.

Use TSYNC/all-thread behavior where available and required. If the process is guaranteed single-threaded at entry, encode and test that precondition rather than assuming it.

Do not import Firecracker's broad allowlist. Build a SynVoid-minimal categorical policy from actual jail needs.

Run representative WASM and YARA round trips under the real filter, including traps/errors/shutdown/restart.

If `seccompiler` fails the architecture/footprint/support gate, document the reason and compare a minimal raw seccomp implementation or `libseccomp`; do not add a C/system dependency by accident.

## Workstream C — FreeBSD Capsicum resource custody

Replace the current "ignore the path arrays then call cap_enter" model with an explicit descriptor-capability plan.

Before `cap_enter`:

- identify every descriptor the jailed workload legitimately needs;
- retain only required descriptors;
- apply `cap_rights_limit` to stdin/stdout/stderr and any preopened file/directory capability;
- apply fcntl/ioctl limits where relevant;
- close accidental inherited descriptors.

Then enter capability mode and verify with `cap_getmode`.

For generic path requests, either preopen the requested roots and expose a descriptor-relative operation contract or report that path-policy form unsupported. Do not pretend a pathname vector itself is a Capsicum allowlist.

Use the maintained Rust `capsicum` crate if it fits the dependency/support target; otherwise keep libc calls only with equivalent rights-limiting coverage and native tests.

Correct the guarantee report:

- ambient global namespaces denied: enforceable;
- descendants inherit confinement: enforceable;
- child creation denied: not implied by Capsicum;
- path allowlist: only if represented through preopened directory capabilities, not raw paths;
- arbitrary new network namespace lookup: denied after capability mode, subject to retained descriptors.

## Workstream D — FreeBSD native tests

On a native FreeBSD qualification host, in separate child processes verify:

- capability mode entered;
- newly opening an unprovided global path fails;
- preopened readable descriptor still reads;
- rights-limited descriptor cannot perform a removed operation;
- creating a new global network endpoint/name lookup fails as expected;
- a forked descendant remains in capability mode;
- report says descendant-confined, not child-creation-denied.

If no maintained FreeBSD qualification host exists, keep the backend experimental and do not promote a support claim from cross-compilation.

## Workstream E — OpenBSD pledge/unveil hardening

Replace lossy `Path::display()` -> C-string conversion with OS-native path bytes and explicit interior-NUL rejection.

Construct unveil rules, then explicitly lock unveil with `unveil(NULL, NULL)` (or prove the exact pledge transition that locks it and test that invariant).

Derive pledge promises from requested guarantees/resource needs. The jail's minimal computation/stdio path should omit `inet`, `proc`, and `exec` unless a workload proves one is required.

Do not add `prot_exec` casually. If Wasmtime/JIT operation requires executable-memory privileges on OpenBSD, test that fact and reflect it as a backend-specific requirement rather than silently broadening every profile.

Add native child-process tests for allowed/denied paths, network denial, child creation, exec, and unveil-lock behavior.

## Workstream F — macOS guarantee report integration

Do not redesign the Phase 46 Seatbelt profile unless the new conformance tests reveal a defect.

Map the existing native-tested strict profile into the new guarantee report:

- filesystem allowlists/denies as actually proven;
- network denial;
- child/exec behavior as proven by native child tests;
- no numeric process-memory guarantee;
- deprecated `sandbox_init` mechanism and experimental support tier.

Keep `macos-sandbox` opt-in and retain the runtime symbol probe.

Do not call this Apple App Sandbox.

## Workstream G — Windows access-isolation launch feasibility gate

Research/prototype a parent-created access-control sandbox separately from the in-place Job Object resource limiter.

Evaluate, on the supported Windows baseline:

1. classic AppContainer profile/token launch;
2. ProcessContainer / current CreateProcess-in-sandbox APIs where available and supportable;
3. inherited stdio/anonymous-pipe access;
4. executable/dynamic-library access;
5. temporary/work directory grants;
6. network default-deny and opt-in rules;
7. interaction with the Job Object resource/lifecycle layer;
8. cleanup/profile lifetime and package-free deployment;
9. ability to preserve the existing dedicated-jail binary resolution and no-PATH/CWD invariant.

This is a decision gate, not a mandate.

If a native launch backend can satisfy the jail contract without broad ACL grants or packaging regressions, implement it behind a separate spawn/preparation path and give it its own guarantee mapping.

If not, explicitly retain:

- Windows Job Object = resource/lifecycle containment;
- Windows access-control guarantees = unsupported;
- `IsolationPolicy::Required` for guarantees Windows cannot supply = fail closed.

Never weaken the required guarantee set merely to make Windows report supported.

## Workstream H — Inherited-resource hygiene across platforms

Use Phase 82's resource model to audit descriptors/handles present at jail entry.

At minimum:

- stdin/stdout are required IPC capabilities;
- stderr is the logging capability;
- no listener, admin, mesh, config, plugin directory, or secret handle may leak into the jail;
- Windows handle inheritance is explicit;
- Unix descriptors not required by the jail are CLOEXEC/closed as appropriate.

Add a regression that enumerates/attempts use of unexpected inherited resources where the platform permits reliable testing.

## Workstream I — Failure and restart semantics

A sandbox policy installation failure must occur before the jail handshake reports ready.

Parent behavior remains:

- quarantine failed child;
- bounded restart/backoff;
- exhaustion => fail closed for `Required`;
- no in-process fallback for required isolation.

Add fault injection for Landlock/seccomp/Capsicum/Pledge/Seatbelt/Windows preparation failures through fake backend hooks where native fault injection is impractical.

## Verification

Common:

    cargo fmt --all -- --check
    cargo test -p synvoid-platform --profile ci
    cargo test -p synvoid-jail-runtime --profile ci
    cargo test --test jail_isolation_guard --profile ci
    cargo xtask test guards
    cargo xtask verify
    cargo deny check
    cargo audit

Native evidence is required for any support claim on Linux, Windows, FreeBSD, OpenBSD, or macOS. Cross-target `cargo check` supplements but never replaces enforcement tests.

## Acceptance criteria

- Linux jail no-network/no-child/no-exec claims are backed by an installed/tested syscall-filter mechanism or remain unsupported;
- seccomp does not break real WASM/YARA jail workloads;
- Capsicum limits retained descriptor rights before entering capability mode;
- Capsicum distinguishes descendant confinement from child creation denial;
- OpenBSD locks unveil and uses non-lossy path conversion;
- OpenBSD pledge promises are derived/minimized and natively tested;
- Seatbelt keeps its existing experimental/deprecated support truth;
- Windows access-control isolation is either natively proven through a dedicated launch path or remains explicitly unsupported;
- inherited jail resources are minimal and tested;
- no platform becomes "supported" from cross-compilation alone.

## Rejection criteria

Reject implementation that:

- introduces a giant Linux syscall allowlist without workload qualification;
- requires system libseccomp without an explicit dependency/packaging decision;
- treats Capsicum as pathname ACLs;
- sets FreeBSD child-denied because descendants inherit capability mode;
- adds broad OpenBSD promises merely to make tests pass;
- turns Windows AppContainer setup into permanent broad host-directory ACL mutation;
- changes macOS distribution/signing architecture incidentally.
