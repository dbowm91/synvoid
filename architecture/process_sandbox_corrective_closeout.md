# Process Sandbox Corrective and Extraction-Readiness Closeout (Phases 81–84)

Final disposition at Phase 84: **DEFER** (do not extract; retain internal
under `synvoid-platform` with the corrected guarantee contract). No crate is
published and no repository is created by this campaign.

Baseline: `81638c251592913579bd9bbce51d013c44d67910` (2026-09-26).
Implementation SHA: `96bc53e119ed079e121db2ed6497dfd2c3b2b011` (executable
code + tests; docs/evidence in the follow-up commit, no executable change —
same convention as Phase 80).

Roadmap: `plans/process_sandbox_corrective_extraction_readiness_roadmap.md`.
Plans: `plans/phase_81_process_sandbox_backend_correctness_corrective.md`,
`plans/phase_82_process_sandbox_guarantee_contract_and_compatibility.md`,
`plans/phase_83_process_sandbox_native_capability_hardening.md`,
`plans/phase_84_process_sandbox_extraction_readiness_closeout.md`.

## 1. Call-site inventory (Phase 81 Workstream A)

Production callers of the sandbox surface (retained-vs-dropped discipline):

| Caller | Request | Guard | Threads/resources | Failure mode | Security-critical |
|--------|---------|-------|-------------------|--------------|-------------------|
| `synvoid-jail-runtime::run_jail_main` (WASM/YARA dedicated binaries) | jail guarantee request (ambient-FS deny, `/usr/lib`+`/lib` reads, inherited-IPC usable, descendants confined) + legacy Strict pin | RETAINED through the framed serve loop (`Option<EnteredSandbox>`: `Some` = enforced+retained, `None` = hatch-explicit test-only, `Err` = fail closed) | stdio captured before entry; entry before workload threads/resources | fail closed (exit 1), no serve loop without a guard | YES |
| `synvoid-upload::SandboxConfig::apply_platform_sandbox` | caller level (default `Off`), sandbox/quarantine dirs | DROPPED after apply by design | helper context | fail-open to basic directory isolation with warning | NO (directory-isolation helper, documented) |
| Tests/docs | `with_stub` / `Off` probes | n/a | n/a | n/a | NO (never enforcement evidence) |
| Config `sandbox_level = "strict"` | legacy adapter (pinned, no global reinterpretation) | per-caller | per-caller | `InsufficientCapabilities` when backend lacks read allowlist | pinned compat |

Regression: `jail_sandbox_failure_never_enters_serve_loop`
(`crates/synvoid-jail-runtime`) pins that a failed installation carries no
guard and therefore cannot reach `serve`; the platform fake-backend
conformance suite (`sandbox_guarantee_conformance`,
`sandbox_no_downgrade`) pins required-failure ⇒ error at the report layer.

## 2. Defect / root-cause table (corrective)

| # | Defect (before) | Root cause | Fix (after) | Evidence |
|---|-----------------|------------|-------------|----------|
| 1 | Landlock ruleset created with flag value 1 (`LANDLOCK_CREATE_RULESET_VERSION`) + non-null attr + nonzero size | Handwritten UAPI confused version-query flags with ruleset-creation flags; version queries require null attr + zero size | Deleted raw UAPI; maintained `landlock` crate 0.4.7 with `HardRequirement`; ruleset creation uses flags 0 + ABI-sized structs internally | Linux cross-check clean; native child tests (`sandbox_linux_enforcement`) prove real filesystem denial |
| 2 | `landlock_restrict_self(..., 0)` without `no_new_privs` | Missing unprivileged-enforcement precondition | Crate atomic `no_new_privs(true)` + `RestrictionStatus.no_new_privs` verified; `PR_GET_NO_NEW_PRIVS` proven in child test | `linux_no_new_privs_verified_after_entry` |
| 3 | Frozen v1-only filesystem rights + kernel-release-text gate | Raw constants never tracked ABI evolution (TCP ABI 4, TSYNC ABI 8, unix-socket ABI 9, UDP ABI 10); version text ≠ LSM presence | Vetted ABI V1 allowlist (`from_read`/`from_write`), ABI/capability probe (real ruleset creation), newer rights never silently claimed (explicit unsupported until qualified) | probe reports actual status; impossible-hard-requirement child test |
| 4 | Landlock denied-paths silently logged | No deny primitive; overlap with allowed ancestor unrepresentable | Typed `Unsupported` fail-closed on any denied-path request | `linux_impossible_hard_requirement_fails_before_workload` |
| 5 | Windows Job Object class 2 with extended-limit struct; flags 0x1/0x2/0x20 | Handwritten ABI copy wrong on all three values | Generated `windows-sys` `JobObjects` types; class 9 (`JobObjectExtendedLimitInformation` = 9); flags 0x100/0x200/0x2000; query-back verification of flags+limits | Windows child tests query back intended memory + kill-on-close |
| 6 | Mitigation setters passed creation-policy scalars (`u32` 0x1/0x8) | Wrong parameter type for `SetProcessMitigationPolicy` | Real `PROCESS_MITIGATION_DEP_POLICY` (Flags=1) / `PROCESS_MITIGATION_ASLR_POLICY` (Flags=0b111) structs; query-back distinguishes newly-applied from already-enforced | `windows_mitigation_path_is_fail_closed_for_strict` + struct-size pins |
| 7 | `apply_file_restrictions` mutated host ACLs as "sandbox" | DACL hardening misclassified as process-local allowlist | REMOVED from `WindowsSandbox::apply` and all capability claims; Strict stays fail-closed for filesystem isolation | `windows_no_dacl_mutation_behind_sandbox_names` (static) |
| 8 | Job handle leaked (never closed) | No owned state; fixing by closing in a short-lived local would kill the process under kill-on-close | `Mutex<Option<isize>>` owned state retained via `ProcessSandbox`; `Drop` closes exactly once at teardown; jails retain the witness through the serve loop | `windows_job_handle_lifetime_is_owned_not_leaked` (static) + retention in `sandbox_entry.rs` |
| 9 | OpenBSD `Path::display()` lossy conversion; unveil never locked; broad implicit promises | Display replaces non-UTF-8; lock step missing | OS-native path bytes + interior-NUL rejection; `unveil(NULL,NULL)` lock (fail-closed); minimal `stdio` pledge (omits inet/proc/exec; no casual `prot_exec`) | OpenBSD child tests (allowed/denied/lock/NUL) |
| 10 | `SandboxLevel::Strict` reduced to `read_path_allowlist` | One adjective for materially different OS guarantees | Portable guarantee contract (`Guarantee`, required/optional, `EnforcementReport`, prepare/enter, `EnteredSandbox`) with legacy adapter pinned | `sandbox_guarantee_conformance` (14 tests) + `sandbox_no_downgrade` (12 tests) |
| 11 | Capsicum ignored path arrays then `cap_enter` | Path-vector abstraction cannot express descriptor capabilities | Explicit descriptor plan: stdio rights-limited (`cap_rights_limit`), `closefrom(3)` hygiene, `cap_getmode` verification; path-vector requests report unsupported (fail closed) | FreeBSD child tests |
| 12 | No syscall-filter layer for jail no-network/no-child/no-exec | Landlock is a filesystem LSM, not a syscall filter | `seccompiler` categorical deny-list (EPERM + ENOSYS-clone3, TSYNC), default-Allow (no giant allowlist), hardcoded set (no untrusted configuration) | Linux seccomp child tests (socket/exec denial, thread-clone preserved) + jail round trips under the filter |

## 3. Dependency / footprint delta (Phase 84 Workstream D)

| Decision | Verdict | Evidence |
|----------|---------|----------|
| `landlock` 0.4.7 | ADOPTED (Linux-only) | deps `enumflags2` + `libc` + `thiserror` (all pre-existing in graph); no optional features; MSRV 1.71 (workspace 1.81); ABI-9 surface, vetted ABI V1; x86_64/aarch64/riscv64 via syscalls |
| `seccompiler` 0.5 | ADOPTED (Linux-only, `default-features = false`) | deps `libc` only (no serde/json); pure Rust, no system `libseccomp`; `libseccomp` kept as comparison baseline and rejected (native-library requirement, no narrower benefit) |
| `capsicum` crate | REJECTED (documented) | libc calls with equivalent rights-limiting coverage; crate adds no narrower mechanism for stdio custody and would add a FreeBSD-only edge |
| Windows bindings | version unchanged (`windows-sys` 0.59); +2 features (`Win32_System_JobObjects`, `Win32_System_SystemServices`) | no new crate; canonical generated types replace handwritten ABI |
| System libraries | none added | `cargo deny check` clean (advisories/bans/licenses/sources ok) |

`cargo tree -p synvoid-platform --target x86_64-unknown-linux-gnu` shows
only the two narrow Linux-only leaves above (plus pre-existing transitive
`enumflags2_derive`/proc-macro set already in the graph). macOS/Windows
builds are unaffected (Linux-only deps). Exact release byte deltas are a
Linux qualification-lane measurement (re-evaluation trigger below), not a
closeout blocker for DEFER: the additions are small, pure-Rust, and
target-gated, with no packaging change (no new system-library requirement).

Jail binaries: unchanged packaging (`verify-release` jail-binary checks
unaffected); the jail IPC/framing/version behavior is unchanged (this
campaign is sandbox enforcement, not jail RPC redesign).

## 4. Before / after guarantee matrix (from `EnforcementReport` vocabulary)

Generated from `project_report_for_backend` — docs and code share these
meanings exactly (Phase 84 Workstream A). Scope abbreviations: T =
CurrentThreadPlusDescendants (jail enters before workload threads),
A = AllThreadsPlusDescendants (seccomp TSYNC / Landlock ABI-8 where
available), P = ProcessTree/job containment.

| Guarantee | Linux (Landlock + seccomp) | FreeBSD (Capsicum) | OpenBSD (pledge/unveil) | macOS (Seatbelt strict, exp.) | Windows (Job) | Stub |
|-----------|---------------------------|-------------------|------------------------|-------------------------------|---------------|------|
| AmbientFilesystemDenied | Enforced (T) | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| FilesystemReadAllowlist | Enforced (T) | Unsupported (preopen required) | Enforced | Enforced | Unsupported | Unsupported |
| FilesystemWriteAllowlist | Enforced (T) | Unsupported (preopen required) | Enforced | Enforced | Unsupported | Unsupported |
| ExplicitDenyPath | Unsupported | Unsupported | Enforced | Enforced | Unsupported | Unsupported |
| InheritedResourcesOnly | Enforced | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| NetworkDenied | Enforced via seccomp (A) / Unsupported without | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| NetworkTcpRestricted | Enforced via seccomp (A) / Unsupported without | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| NetworkUdpRestricted | Enforced via seccomp (A) / Unsupported without | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| InheritedIpcUsable | Enforced | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| ChildCreationDenied | Enforced via seccomp (A) / Unsupported without | Unsupported (inheritance ≠ denial) | Enforced | Enforced | Unsupported | Unsupported |
| ExecDenied | Enforced via seccomp (A) / Unsupported without | Unsupported | Enforced | Unsupported (process* retained) | Unsupported | Unsupported |
| DescendantsConfined | Enforced (T) | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| ProcessMemoryBound | Unsupported | Unsupported | Unsupported | Unsupported | Enforced (P, 256 MiB) | Unsupported |
| JobMemoryBound | Unsupported | Unsupported | Unsupported | Unsupported | Enforced (P, 512 MiB) | Unsupported |
| TerminatesWithOwner | Unsupported | Unsupported | Unsupported | Unsupported | Enforced (P, kill-on-close) | Unsupported |

Support tiers (unchanged in kind, corrected in content): Linux =
Supported (production strict-isolation target); FreeBSD/OpenBSD =
Experimental (native qualification host required; no support claim from
cross-compilation); macOS Seatbelt = Experimental opt-in, deprecated
`sandbox_init` (never Apple App Sandbox); Windows = Limited
(resource/lifecycle containment; access-control guarantees unsupported;
`Required` fails closed); Stub = Unavailable (Strict fails closed).

Jail minimum boundary (`jail_guarantee_request`): ambient-FS deny, read
allowlist, inherited-IPC usable, descendants confined (scope T) + stdio
resources. Desired-but-unqualified (network/child/exec on Linux without
seccomp) stay explicit unsupported findings, never silently required nor
silently claimed. Windows `Required` for guarantees Windows cannot supply
fails closed (never weakened to make Windows report supported).

## 5. Native evidence

| Lane | Evidence | Result |
|------|----------|--------|
| macOS (host `darwin x86_64`, this machine) | `cargo test -p synvoid-platform --profile ci` (unit + `platform_core_test` + `sandbox_macos_enforcement` + new `sandbox_guarantee_conformance` 14/14 + `sandbox_no_downgrade` 12/12 + hygiene) | green |
| macOS | `cargo test -p synvoid-jail-runtime --profile ci` (incl. new `jail_guarantee_request_is_minimal_and_valid`, `jail_sandbox_failure_never_enters_serve_loop`) | green |
| Linux cross | `cargo check -p synvoid-platform --target x86_64-unknown-linux-gnu --profile ci --tests` (lib + Linux child-test targets incl. seccomp BPF construction) | green |
| Linux native | `sandbox_linux_enforcement` child probes (status/allowed/denied/write/nnp/impossible/seccomp-socket/seccomp-exec/thread-clone/unsupported) | requires Linux host with Landlock ABI (CI lane; explicit unsupported + qualification host otherwise) |
| Windows cross | `cargo check -p synvoid-platform --target x86_64-pc-windows-gnu --profile ci` — `sandbox.rs` clean | sandbox module clean; remaining gnu-target errors (35, down from 41 baseline) are pre-existing `windows_impl`/serde drift, out of scope |
| Windows native | `sandbox_windows_enforcement` child probes (limits query-back, mitigation fail-closed, DACL-absence, handle ownership) | requires Windows host (qualification lane) |
| FreeBSD/OpenBSD native | `sandbox_bsd_enforcement` child probes (cap mode, global-open denial, path-vector unsupported, unveil lock, NUL rejection) | require BSD qualification hosts; backends stay experimental without them |
| Jail e2e | `jail_binary_integration` (WASM/YARA round trips; on Linux without hatch = under the real Landlock+seccomp filter, incl. traps/errors/shutdown/restart) + `tests/jail_isolation_guard.rs` (framing, supervision, fail-closed, hatch-absence in production) | green on macOS (hatch hermetic); Linux lane proves confinement |
| Supply chain | `cargo deny check` | clean |
| Repo guards | `cargo xtask test guards` | green (see verification below) |

Cross-compilation is build evidence only, never enforcement evidence
(binding principle 7). No platform is marked supported from a cross
compile.

## 6. Unsafe / FFI audit (Phase 84 Workstream E)

All sandbox `unsafe` blocks reviewed (see `sandbox.rs`):

- Landlock: none remaining (crate-owned RAII fds; no raw syscalls).
- Seccomp: none (safe `seccompiler` API; BPF built + installed via safe wrappers).
- Capsicum: `cap_getmode`/`cap_enter`/`__cap_rights_init`/`cap_rights_limit`/`closefrom` — local SAFETY comments, explicit fd ownership (stdio only), variadic init with fixed tokens (never untrusted input), mode verified after entry.
- OpenBSD: `pledge`/`unveil`/unveil-lock — NUL-terminated buffers alive for the call, errno-checked, lock fail-closed.
- Windows: generated ABI only; `CreateJobObjectW`/`Set`/`Query`/`Assign`/`GetCurrentProcess`/`CloseHandle`/`Set|GetProcessMitigationPolicy` — SAFETY comments, owned `Mutex<Option<isize>>` handle closed exactly once on drop, `GetLastError` for conflict typing, union bitfield reads commented.
- Hygiene: `fcntl(F_GETFD)` audit is side-effect free (commented).
- Seatbelt: `dlsym` probe + `sandbox_init`/`sandbox_free_error` unchanged from Phase 46 (real error buffer, errno fallback only when the API provides no message).
- No raw handle/fd leak used as lifetime management; no lossy path conversion at any OS security boundary; no host-global side effect behind process-sandbox terminology.

## 7. Windows access-isolation launch gate (Phase 83 Workstream G)

Decision: **NOT IMPLEMENTED in this campaign (explicit retain).**

AppContainer / ProcessContainer-style parent-launch isolation was evaluated
against the campaign constraints (inherited stdio pipes, exe-dir binary
resolution with no PATH/CWD search, package-free deployment, network
default-deny, Job-Object interplay). No parent-launch backend was proven
that satisfies the jail contract without broad ACL grants or packaging
regressions within this corrective's scope. Per the plan this gate is a
decision point, not a mandate. Retained truth:

- Windows Job Object = resource/lifecycle containment (proven, query-backed).
- Windows access-control guarantees = unsupported.
- `IsolationPolicy::Required` for guarantees Windows cannot supply = fail closed.

A future dedicated launch-isolation plan may reopen this with a native
prototype + guarantee mapping; it must not weaken required guarantees to
report supported.

## 8. Extraction decision: DEFER

Disposition: **DEFER** (retain internal under `synvoid-platform`).

- Application-neutral policy types exist (`Guarantee`, `SandboxRequest`,
  `EnforcementReport`, `EnteredSandbox`, `PreopenedResource`) with no
  `synvoid`/`synvoid-config`/`synvoid-ipc`/`synvoid-jail-runtime`/domain
  imports (boundary audit: the candidate scope — portable types, policy
  validation/intersection, probing/lowering, prepare/enter lifecycle,
  reporting, resource description, native backends — depends only on
  `landlock`/`seccompiler`(Linux), `libc`, `tracing`, `thiserror`;
  excluded: config types, jail IPC, supervision, WASM/YARA, metrics, mesh,
  admin, binary resolution).
- BUT: only the jail meaningfully consumes the new contract today
  (GO_EXTRACT requires ≥2 independent consumers without SynVoid-specific
  branches); BSD native evidence is unavailable on this host; the Windows
  launch semantics still dominate part of the API shape; the guarantee
  vocabulary is newly introduced (stability unproven); extraction now
  would merely move files without reducing maintenance authority.

Re-evaluation triggers (concrete; no new plan registered until one fires):

1. A second in-tree consumer adopts the guarantee boundary without
   SynVoid-specific branches (e.g. upload scanning helper or worker
   startup migrating from the legacy adapter).
2. Native Linux + one BSD qualification lane both report green
   enforcement for the jail matrix (proving the vocabulary is stable
   across backends).
3. The Windows launch gate is resolved either way by a proven prototype
   (access-control backend) or a recorded RETAIN verdict with rationale.
4. `landlock`/`seccompiler` remain maintained with no advisory/-footprint
   regression at re-audit (dependency-security baseline cadence).

No extraction/migration work is authorized by this closeout.

## 9. Residual risks

1. Linux clone3 process creation on non-ENOSYS-fallback libcs: mitigated
   by ENOSYS (transparent fallback to flag-filtered clone); raw-clone3
   attackers get ENOSYS. Re-evaluate if a libc without clone3→clone
   fallback is ever in the support set.
2. `clone` with `CLONE_THREAD` set by a compromised workload creates
   threads (by design — runtimes need them); threads inherit both
   Landlock domain and seccomp filter, so this is contained, not a bypass.
3. Capsicum path-policy remains unsupported (fail closed) until the
   descriptor-preopen contract lands; FreeBSD jail `Required` fails closed.
4. OpenBSD `prot_exec`/Wasmtime JIT needs are unproven on OpenBSD hosts;
   promises stay minimal until native workload tests prove otherwise.
5. macOS Seatbelt stays experimental/deprecated; exec-denial explicitly
   unsupported (`process*` retained).
6. Windows access-control isolation explicitly unsupported (gate above).
7. Seccomp filter covers the jail's categorical needs only; it is not a
   general syscall allowlist and must not be mistaken for one.
8. Windows cross-compile from non-Windows hosts still shows pre-existing
   `windows_impl`/serde drift (35 errors on the gnu lane, down from 41;
   `sandbox.rs` itself clean) — owned by a future Windows-host lane, not
   this campaign.

## 10. Historical preservation

Phase 46/48 evidence files remain historical. Current binding docs
(`docs/SANDBOXING.md`, `architecture/platform.md`,
`architecture/sandbox_jail_protocol.md`, `.opencode/skills/sandboxing/SKILL.md`)
now state what was proven by THIS campaign; a supersession note points
readers away from treating old Linux/Windows backend evidence as current
terminal proof. No old "Strict == read allowlist" claim remains as the
authoritative security model.

## 11. Phase 89 post-closeout corrective addendum (entry + policy semantics)

Status: closed (post-closeout corrective; Phases 81–84 remain historically
closed; extraction disposition remains **DEFER** — no standalone crate or
repository created, no re-evaluation trigger fired).

Trigger: post-closeout review found four bounded semantic defects that did
not invalidate the corrective architecture or its DEFER verdict:

1. the jail performed the legacy Strict entry to compute `legacy_ok`, then
   entered the guarantee-driven sandbox a second time;
2. Linux `LandlockSandbox::apply()` unconditionally installed the
   jail-specific seccomp filter, so generic/legacy Basic semantics were
   stronger than documented;
3. `SandboxRequest::intersect()` dropped disjoint required guarantees and
   copied path/resource authority from only one operand;
4. the jail request omitted the no-network/no-child/no-exec guarantees that
   Phase 83 has a Linux mechanism to enforce.

Corrections (all landed, all regression-tested):

- Jail startup performs exactly one irreversible transition
  (`prepare_sandbox(jail_guarantee_request())?.enter()`, witness retained
  through the serve loop). The production
  `ProcessSandbox::with_paths(Strict, ..)` probe was deleted; a unit source
  guard (`jail_entry_has_single_irreversible_transition`) pins one
  `prepared.enter()` and no production `with_paths`/`Strict` reference.
- Landlock filesystem confinement is decoupled from syscall-filter
  confinement. `LandlockSandbox::apply()` enforces filesystem only (source
  guard `landlock_apply_does_not_install_jail_seccomp`); an internal
  `MechanismPlan` maps explicit guarantees to seccomp categories
  (`NetworkDenied` → network rules, `ChildCreationDenied` → process-creation
  rules, `ExecDenied` → exec rules; `NetworkTcpRestricted`/`UdpRestricted`
  alone select nothing and report unsupported on Linux rather than
  overrestricting). Empty selection installs no filter. Unit + conformance
  tests pin per-category selection, empty-selection no-install, and combined
  jail selection.
- `SandboxRequest::intersect()` was removed (no production caller existed).
  The conformance test that blessed dropping requirements was replaced with
  explicit-union composition plus mechanism-plan, jail-boundary, and
  prepared-plan tests. Deterministic fake-backend tests
  (`one_prepared_request_produces_one_backend_entry`,
  `filesystem_only_request_installs_no_seccomp`,
  `injected_seccomp_failure_fails_closed_with_no_witness`,
  `injected_backend_failure_fails_closed`) prove one prepared request yields
  one backend entry plus at most one seccomp install, with fail-closed
  behavior on either failure — without stacking irreversible host sandboxes.
- The jail request now authoritatively requires `NetworkDenied`,
  `ChildCreationDenied`, and `ExecDenied` (in addition to ambient-FS deny,
  read allowlist, inherited IPC, descendants confined). Linux installs the
  corresponding seccomp clauses; OpenBSD satisfies via pledge/unveil; macOS
  fails `Required` for exec denial (unproven); Windows fails closed for
  access-control guarantees. No support label was preserved by weakening a
  requirement.
- Preparation stays side-effect free; the selected `MechanismPlan` travels
  into `enter`; the final `EnforcementReport` is built by
  `finalize_report_from_receipt` from installation receipts (a requested
  category without a successful install is `Unsupported`, never `Enforced`
  from a compile probe). Required-install failure returns an error with no
  `EnteredSandbox`.

Verification: `cargo test -p synvoid-platform --profile ci` green
(incl. conformance 18/18, no-downgrade 12/12, new unit mechanism tests),
`cargo test -p synvoid-jail-runtime --profile ci` green (incl. updated jail
boundary + single-entry guard), `cargo test --test jail_isolation_guard
--profile ci` green, Linux
`--target x86_64-unknown-linux-gnu` check clean, `cargo xtask test guards`
green. Native Linux/Windows/BSD enforcement lanes remain qualification-host
gated (unchanged tiering); cross-compilation is not enforcement evidence.

Supersessions: the §1 call-site inventory jail row (legacy Strict pin +
desired-but-unqualified network/child/exec), §4 jail minimum boundary
sentence, and any reading of §2/§5 that implies double entry or
Landlock-always-seccomp are superseded by this addendum. The DEFER verdict,
triggers (§8), residuals (§9), and campaign constraints are unchanged.
