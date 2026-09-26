# Process Sandbox Corrective and Extraction-Readiness Roadmap

Status: planned (2026-09-26).

Baseline: `81638c251592913579bd9bbce51d013c44d67910`.

Predecessors:

- `plans/phase_46_platform_sandbox_truthfulness_and_macos_closure.md`
- `architecture/runtime_truthfulness_security_publication_closeout.md`
- `plans/crate_boundary_reuse_followup_roadmap.md`
- `architecture/sandbox_jail_protocol.md`

Primary goal: correct the native sandbox backends before any standalone extraction, replace the ambiguous cross-platform "Strict" contract with explicit enforceable guarantees, harden the BSD/Linux/Windows capability boundaries, and leave a small application-neutral process-sandbox boundary that can be evaluated for extraction without weakening SynVoid.

This is a corrective security campaign, not a crate-count campaign. Runtime correctness and truthful enforcement claims come before extraction.

## Research findings that trigger this campaign

### Linux Landlock correctness

The canonical Linux backend in `crates/synvoid-platform/src/sandbox.rs` manually issues the Landlock syscalls. The current ruleset-creation path passes flag value 1 together with a non-null attribute and nonzero size. In the Landlock UAPI, that flag is `LANDLOCK_CREATE_RULESET_VERSION`; version/errata queries require a null attribute and zero size. The current production ruleset construction therefore does not match the kernel ABI.

The current backend also calls `landlock_restrict_self(..., 0)` without first establishing `no_new_privs`. Unprivileged Landlock enforcement requires either the relevant privilege or `no_new_privs`; current kernel documentation recommends setting it even where privilege would make enforcement possible.

The raw backend additionally owns a frozen set of older filesystem rights while the Landlock ABI now evolves independently: TCP restrictions begin at ABI 4, process-wide TSYNC is available from ABI 8, pathname Unix-socket resolution is ABI 9, and UDP restrictions are ABI 10. A reusable security library should not infer semantic strength from a kernel-version string.

Preferred remediation is the maintained Rust `landlock` crate rather than continuing to duplicate the UAPI. As of this plan, `landlock` 0.4.7 exposes ABI-aware access sets through ABI 9, hard/soft/best-effort compatibility levels, explicit enforcement status, default `no_new_privs`, and process-wide enforcement support where the running ABI supports it. The dependency/footprint delta must still be measured before adoption; if the safe crate is rejected, the raw implementation must implement the same ABI-aware contract and tests.

References:

- https://docs.kernel.org/userspace-api/landlock.html
- https://docs.rs/landlock/latest/landlock/
- https://docs.rs/landlock/latest/landlock/trait.Compatible.html

### Windows Job Object and mitigation correctness

The current Windows backend redefines Job Object ABI structures and constants locally. The implementation passes information-class value 2 while supplying an extended-limit structure; `JobObjectExtendedLimitInformation` is class 9. It also encodes the process-memory, job-memory, and kill-on-close flags as 0x1, 0x2, and 0x20 rather than the documented 0x00000100, 0x00000200, and 0x00002000 values.

The current mitigation path passes scalar creation-policy constants to `SetProcessMitigationPolicy`; that API expects the corresponding process-mitigation structures. This must be corrected with generated Windows bindings rather than another handwritten ABI copy.

The current DACL path is not process sandboxing: it mutates ACLs on host filesystem objects and does not create a deny-by-default filesystem view for only the sandboxed process. It must not be represented as a filesystem allowlist.

Job Objects are useful resource/process-tree containment, not an access-control sandbox. AppContainer/ProcessContainer-style launch isolation is a separate mechanism and generally belongs to parent-side child creation rather than `enter_current_process()`. That architectural mismatch must be preserved honestly unless a dedicated parent-launch backend is proven.

References:

- https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
- https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
- https://learn.microsoft.com/windows/win32/procthread/job-objects
- https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy
- https://learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation
- https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/processthreadsapi.h

### BSD semantic mismatch

Capsicum is descriptor-capability based. `cap_enter()` removes ambient global namespace access but deliberately keeps already-open descriptors usable; descendants created by `fork` or `pdfork` remain in capability mode. Correct confinement therefore requires pre-opening inherited resources and narrowing them with `cap_rights_limit`, `cap_fcntls_limit`, and `cap_ioctls_limit` as appropriate. A path-vector-only abstraction cannot express this faithfully.

OpenBSD has a different contract. `unveil` creates the filesystem view and should be locked after policy construction; `pledge` then removes operation classes. In particular, a `stdio` pledge omits the `proc` and `exec` promises, so child creation and exec can be denied rather than merely inherited as confined.

References:

- https://man.freebsd.org/cgi/man.cgi?query=cap_enter&sektion=2
- https://docs.rs/capsicum/latest/capsicum/
- https://man.openbsd.org/unveil
- https://man.openbsd.org/pledge.2

### Linux syscall-filter layer

Landlock is an ambient-resource access-control LSM, not a general syscall filter. SynVoid jails use inherited stdio pipes and should not need to create network sockets, spawn child processes, or exec new programs after entry. A small seccomp layer can express those guarantees without turning the jail into a brittle full syscall allowlist.

The preferred implementation candidate is `seccompiler`: it is pure Rust, supports x86_64/aarch64/riscv64, and avoids adding a system `libseccomp` dependency. `libseccomp` remains a comparison baseline but requires the native library. The implementation phase must use targeted negative rules or a carefully qualified profile rather than copy a Firecracker-specific allowlist.

References:

- https://docs.rs/seccompiler/latest/seccompiler/
- https://docs.rs/libseccomp/latest/libseccomp/
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md

## Binding principles

1. A sandbox may only claim guarantees the active backend actually enforces.
2. A required guarantee must fail before untrusted work begins if it is unsupported, partially enforced, or could not be installed.
3. "Children inherit confinement" and "child creation is denied" are different guarantees.
4. Resource limits, access-control isolation, syscall filtering, and lifecycle containment are separate mechanisms even if one backend combines them.
5. Irreversible self-restriction must happen after required inherited resources are established and before untrusted workload execution.
6. Backend-owned resources whose lifetime is security-significant must be represented by an owned entered-sandbox guard, not leaked raw handles.
7. Cross-compilation is build evidence, not native enforcement evidence.
8. The historical `SandboxLevel` / `SandboxPaths` API remains a compatibility surface until call sites are deliberately migrated; do not silently reinterpret user configuration.
9. Do not publish or create a standalone repository during this campaign. Phase 84 records a GO/DEFER extraction decision and registers later work if warranted.
10. Keep `src/platform/` a compatibility facade. Canonical mechanism remains under `crates/synvoid-platform` until an explicit later extraction.

## Execution order

### Phase 81 — Native backend correctness corrective

Plan: `plans/phase_81_process_sandbox_backend_correctness_corrective.md`.

Repair the known Landlock and Windows ABI defects first. Add native child-process evidence so a backend cannot be classified as enforced because a probe or compile succeeded. Do not introduce the new portable guarantee API yet.

### Phase 82 — Guarantee contract and compatibility migration

Plan: `plans/phase_82_process_sandbox_guarantee_contract_and_compatibility.md`.

Replace `can_enforce_strict() == read_path_allowlist` with explicit required/optional guarantees, an enforcement report, prepare/enter staging, thread-scope truth, and an owned `EnteredSandbox` lifetime token. Preserve legacy adapters and migrate the jail path deliberately.

### Phase 83 — Native capability hardening

Plan: `plans/phase_83_process_sandbox_native_capability_hardening.md`.

Add only the native mechanisms needed to satisfy useful guarantees: Linux seccomp for no-network/no-child/no-exec where qualified, Capsicum preopened descriptor rights, OpenBSD unveil/pledge hardening, existing Seatbelt report integration, and a Windows AppContainer/ProcessContainer feasibility gate rather than a false self-entry abstraction.

### Phase 84 — Requalification and extraction-readiness closeout

Plan: `plans/phase_84_process_sandbox_extraction_readiness_closeout.md`.

Reconcile documentation, native evidence, guards, dependency/footprint effects, jail behavior, and reusable-library classification. Produce the extraction decision; do not publish automatically.

## Campaign acceptance criteria

The campaign is complete only when:

- the Linux backend uses valid Landlock ABI construction and proves `no_new_privs` plus actual filesystem enforcement in a child process;
- required Landlock features cannot silently become best-effort;
- Windows Job Object limits use generated ABI definitions and native query evidence;
- Windows filesystem ACL mutation is no longer represented as process-local filesystem sandboxing;
- resource/lifecycle handle ownership is explicit and leak-free;
- portable policy asks for concrete guarantees, not a platform-relative adjective;
- the enforcement report distinguishes enforced, unsupported, and degraded/partial results and identifies the backend and thread/process scope;
- required guarantees fail closed before jail workload execution;
- Capsicum policy is descriptor-capability aware;
- OpenBSD policy locks unveil and derives truthful pledge promises;
- Linux no-network/no-child/no-exec claims, if made, have a separately tested syscall-filter layer;
- macOS remains explicitly experimental deprecated Seatbelt unless a different signed-helper architecture is separately implemented;
- Windows remains limited unless an actual access-control launch boundary is proven;
- jail IPC ordering and fail-closed `IsolationPolicy::Required` semantics are preserved;
- default/minimal profiles and release packaging remain green;
- a final extraction assessment identifies the application-neutral API/dependency boundary and either registers later extraction work or records DEFER with concrete blockers.

## Rejection criteria

Reject closeout that:

- treats successful compilation or syscall presence as enforcement proof;
- preserves raw ABI constants after generated/safe bindings are available without a measured reason;
- uses best-effort Landlock while reporting a required guarantee as enforced;
- equates Job Objects with AppContainer;
- mutates host ACLs and calls that a process-local path allowlist;
- calls inherited confinement a ban on child creation;
- makes FreeBSD path-vector semantics pretend Capsicum is path based;
- broadens a Linux seccomp profile without workload tests;
- changes existing `sandbox_level` configuration semantics as an incidental refactor;
- adds a new public crate before the closeout decision.
