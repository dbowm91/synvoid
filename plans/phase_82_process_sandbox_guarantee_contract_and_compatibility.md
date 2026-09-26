# Phase 82 Plan: Process Sandbox Guarantee Contract and Compatibility Migration

Status: planned (2026-09-26).

Roadmap: `plans/process_sandbox_corrective_extraction_readiness_roadmap.md`.

Depends on: Phase 81 backend correctness.

Primary goal: replace the platform-relative `SandboxLevel::Strict` capability decision with a small application-neutral contract describing the guarantees a caller requires and exactly what the backend installed.

## Problem statement

Today `SandboxCapabilities::can_enforce_strict()` is equivalent to `read_path_allowlist`. That makes "Strict" mean different things on different operating systems and misses important distinctions:

- Landlock can confine filesystem access while still allowing process creation unless another mechanism blocks it;
- Capsicum allows descendants but keeps them in capability mode;
- OpenBSD can deny `proc` and `exec` with pledge;
- Windows Job Objects constrain a process tree but are not an access-control sandbox;
- Seatbelt strict currently combines filesystem, network, and child restrictions;
- a resource limit is not the same class of guarantee as namespace/access confinement.

A standalone crate cannot safely expose one adjective in place of those semantics.

## Workstream A — Define the guarantee vocabulary

Introduce a non-SynVoid-specific guarantee vocabulary under `synvoid-platform::sandbox`. Exact naming may change during implementation, but the contract must distinguish at least:

Filesystem/access:

- ambient filesystem namespace denied/restricted;
- read allowlist enforced;
- write allowlist enforced;
- explicit deny path enforced;
- inherited/preopened resource only.

Network:

- creation/use of new external network sockets denied;
- outbound TCP restricted;
- outbound UDP restricted;
- inherited IPC descriptors remain usable.

Process/execution:

- child process creation denied;
- exec/new-program execution denied;
- descendants inherit confinement;
- process-wide versus calling-thread-only enforcement.

Resources/lifecycle:

- process memory bound;
- aggregate job/process-tree memory bound;
- confinement ends/terminates with owning supervisor or job handle, where applicable.

Do not model "child_process_restrictions" as one boolean. Inheritance and creation denial are separate.

Keep the enum/set extensible and non-exhaustive if it becomes public within the workspace.

## Workstream B — Required versus optional guarantees

Add a request type equivalent to:

- required guarantees: failure to install or prove any one of them aborts before untrusted work;
- optional guarantees: may be applied opportunistically but are reported honestly;
- resource/path/preopened inputs needed by the selected backend.

Backend selection must produce a typed unsupported/degraded reason rather than a warning-only path.

Do not let a backend silently lower a required guarantee because its OS lacks the feature.

## Workstream C — Prepare then enter

Split policy compilation/probing from irreversible confinement.

The lifecycle must be:

1. validate policy/resource inputs;
2. probe backend and lower portable requirements;
3. produce a prepared plan plus a pre-entry enforcement projection;
4. establish required inherited/preopened resources;
5. enter the sandbox irreversibly;
6. return an entered-sandbox witness containing the final enforcement report and any security-significant backend state;
7. begin untrusted workload.

Preparation must have no irreversible host/process side effect.

`enter` must be the single irreversible boundary.

## Workstream D — Enforcement report

Add an immutable report that records:

- backend identity;
- backend/runtime version or ABI where meaningful;
- each requested guarantee;
- status: enforced, unsupported, degraded/partial, or not requested;
- mechanism responsible for enforcement;
- thread/process scope;
- any version/host condition that limited the result.

A required guarantee must never be present as degraded/unsupported in a successful `EnteredSandbox`.

Keep report fields bounded and free of secret paths unless a caller explicitly asks for diagnostic path detail. Normal metrics/logging should use fixed guarantee/backend identifiers.

## Workstream E — EnteredSandbox lifetime witness

Introduce a non-cloneable `EnteredSandbox` or equivalent guard.

It serves two purposes:

1. typed evidence that the irreversible transition succeeded;
2. ownership of backend state that must live as long as confinement, especially Windows Job handles.

Dropping the token must not silently remove restrictions on platforms where restriction is irreversible. Where a handle controls lifetime/kill-on-close, document and test drop semantics explicitly.

For long-lived jails, retain the token through the framed serve loop. Do not create it in a helper and discard it before processing work.

## Workstream F — Thread-scope truth

Make enforcement scope explicit.

Landlock before ABI 8 can restrict the calling thread and descendants without synchronizing sibling threads. Newer Landlock can request all-thread enforcement. The SynVoid jail currently enters before workload-created threads, which can satisfy its call-site invariant even on an older ABI; a reusable API cannot assume that ordering.

Represent at least:

- current thread + future descendants;
- all current threads + future descendants;
- process-tree/job containment where applicable.

A caller that requires all-current-thread enforcement must fail if the backend cannot provide it.

## Workstream G — Resource representation

Introduce an application-neutral representation for resources that must exist before entry.

At minimum support inherited/preopened file descriptors/handles with declared intent such as read, write, metadata, or IPC. This is needed for Capsicum and is useful for documenting the jail's inherited stdin/stdout transport.

Do not force every backend to use descriptor capabilities. Path-based backends can lower path policy directly while still reporting inherited resources separately.

Avoid adding generic command-spawn/process-supervisor APIs in this phase.

## Workstream H — Compatibility layer

Preserve existing `SandboxLevel`, `SandboxPaths`, `ProcessSandbox::new`, and `with_paths` long enough to migrate internal callers safely.

Rules:

- mark them as legacy/workspace compatibility in docs rather than promising new standalone stability;
- do not reinterpret existing `sandbox_level = "strict"` configuration globally;
- implement the legacy path as a narrow adapter over the new mechanism where possible;
- add tests pinning existing Off/Basic/Strict configuration behavior until an explicit config migration is planned;
- prohibit new production call sites from using the legacy `can_enforce_strict()` gate.

No external semver promise is required for `synvoid-platform`, but internal regressions are still not acceptable.

## Workstream I — Migrate jail policy first

Migrate `crates/synvoid-jail-runtime/src/sandbox_entry.rs` to the guarantee API.

The jail has a particularly clean lifecycle:

- inherited stdio exists before sandbox entry;
- module/rule bytes arrive over that IPC;
- it should need no new network authority;
- it should not spawn child programs;
- security-sensitive `IsolationPolicy::Required` already fails closed.

Define the jail requirements from actual workload needs rather than the old word "Strict".

Do not demand a guarantee the current backend cannot yet provide merely to force Phase 83 early. Instead:

- required guarantees must correspond to the minimum security boundary SynVoid is willing to call `Required`;
- missing desired guarantees remain explicit unsupported/degraded findings and are Phase 83 work;
- if current Linux is judged insufficient without no-network/no-child/no-exec, keep required jail routing fail-closed until Phase 83 supplies them.

Preserve parent-created stdio ordering and the test-only no-sandbox hatch behavior.

## Workstream J — Backend conformance tests

Create a table-driven policy/guarantee conformance suite independent of any one OS.

Test:

- required unsupported => error;
- required degraded => error;
- optional unsupported => success + report;
- report cannot say enforced when backend returns partial;
- guarantee sets only narrow when composed/intersected;
- no legacy adapter can turn a failed required guarantee into Basic/off;
- entered token lifetime is retained through jail execution.

Use fake backends for deterministic semantic tests and native child tests for actual enforcement.

## Acceptance criteria

- no security decision is based solely on `can_enforce_strict() == read_path_allowlist`;
- required/optional semantics are typed and tested;
- enforcement status is machine-readable;
- child-denied and descendants-confined are distinct;
- thread scope is explicit;
- resource limits are distinct from access-control guarantees;
- preopened/inherited resources can be represented without SynVoid-specific types;
- irreversible entry returns an owned witness;
- the jail retains that witness for its full serving lifetime;
- legacy configuration/API behavior remains pinned while new production code uses the guarantee contract;
- no root `synvoid`, config, mesh, metrics, or jail protocol type leaks into the reusable policy types.

## Rejection criteria

Reject implementation that:

- simply renames `SandboxCapabilities`;
- adds a numeric "strength" score or a new Basic/Strict ladder;
- treats partially enforced required policy as success;
- makes `EnteredSandbox` cloneable without a reason;
- puts supervisor/jail-specific policy in the low-level crate;
- changes existing config strings or defaults without a dedicated migration.
