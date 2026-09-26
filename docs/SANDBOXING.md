# Sandboxing Guide (Phases 46, 81–84 corrective truthfulness; Phase 89 entry/policy semantics corrective)

SynVoid uses OS-level sandboxing to limit the damage potential of a compromised process. The sandbox restricts what resources (files, network, process creation) a compromised worker/jail process can access.

**Linux is the production recommendation for strict jail isolation.** Other backends are experimental/limited (see support tiers). `SandboxCapabilities::process_limits` means numeric resource bounds (memory/process-count, Job-Objects style), not generic syscall filtering.

**Portable guarantee contract (Phase 82):** new production code requests
explicit guarantees (`Guarantee`: filesystem allowlists, explicit deny,
network/child/exec denial, descendant confinement, memory bounds,
owner-termination) as required (fail closed when unsupported/degraded) or
optional (honestly reported), with thread-scope truth (`ThreadScope`) and a
machine-readable `EnforcementReport`. Irreversible entry returns a
non-cloneable `EnteredSandbox` witness retained through the workload.
`SandboxLevel::Strict` remains only as a pinned legacy adapter (Strict =
read-allowlist gate; no global reinterpretation). Never gate new code on
`can_enforce_strict()` alone. Full vocabulary and backend matrix:
`architecture/process_sandbox_corrective_closeout.md` §4 (generated from the
same `EnforcementReport` meanings as the code).

## Support tiers

| Platform | Backend | Min requirement | Tier | Native evidence |
|----------|---------|-----------------|------|-----------------|
| Linux | Landlock (`landlock` crate 0.4.x, ABI-v1 vetted, `HardRequirement`) + seccomp categorical filter (`seccompiler`, EPERM + ENOSYS-clone3, TSYNC) | Landlock ABI (probed via real ruleset creation, never version text) + supported arch (x86_64/aarch64/riscv64) | **Supported** | Linux child enforcement tests (`sandbox_linux_enforcement`: allowed/denied reads+writes, `PR_GET_NO_NEW_PRIVS`, impossible-requirement refusal, socket/exec denial, thread-clone preserved) + jail round trips under the real filter |
| FreeBSD | Capsicum (capability mode, stdio rights-limited, `closefrom(3)`, `cap_getmode`-verified) | FreeBSD 10+ with capsicum(4) | **Experimental** | FreeBSD child tests (`sandbox_bsd_enforcement`); path-vector policy reports unsupported (fail closed) until descriptor preopen lands; no support claim from cross-compilation |
| OpenBSD | Pledge + Unveil (native path bytes, interior-NUL rejection, unveil locked, minimal `stdio` promises) | OpenBSD 5.9+ | **Experimental** | OpenBSD child tests (allowed/denied, unveil lock, NUL rejection) |
| macOS | Seatbelt via deprecated `sandbox_init` | macOS 10.10+, `macos-sandbox` feature **and** runtime `sandbox_init` symbol | **Experimental** (opt-in) | Native child-process tests on macOS host (`sandbox_macos_enforcement`, requires `--features macos-sandbox`); cross-compile alone is not evidence; exec-denial explicitly unsupported (`process*` retained) |
| Windows | Job Objects (generated ABI, class 9, query-verified 256 MiB proc / 512 MiB job / kill-on-close) + DEP/ASLR structures | Windows Vista+ | **Limited** (process limits only) | Windows child tests (`sandbox_windows_enforcement`); access-control guarantees unsupported (`Required` fails closed); no host ACL mutation (removed) |
| Other | Stub | — | **Unavailable** | Strict fails closed |

`Platform::supports_sandbox()` is a coarse gate reporting only Linux/musl + FreeBSD + OpenBSD. macOS/Windows availability is per-backend `is_supported()` (Seatbelt: feature + `dlsym` probe; Windows Job Objects: always on Windows). "Compiled with feature" is not "runtime backend available": Strict fails closed when the runtime is absent.

## Sandbox levels

| Level | Description |
|-------|-------------|
| `Off` | No sandboxing applied |
| `Basic` | Minimal restrictions (see per-backend semantics below) |
| `Strict` | Full restrictions via read-path allowlist; requires a backend with `read_path_allowlist`. Otherwise `ProcessSandbox::with_paths` returns `InsufficientCapabilities` (fail closed). Jail children use the guarantee contract (`jail_guarantee_request()` → `prepare_sandbox` → `enter`, exactly one irreversible transition), not the legacy `Strict` word. |

### Basic semantics (Phase 46)

- **Landlock**: filesystem allowlists enforced (same primitive as Strict); no network/process/child limits (Landlock provides none).
- **Capsicum**: enter capability mode (global-namespace restriction); no path allowlists.
- **Pledge**: unveil allowlists + `pledge("stdio")` syscall restriction.
- **Seatbelt**: `(allow default)` permissive policy with explicit denies for `no_access_paths`; read/write lists emitted as explicit allows for documentation. Claims **no** network/child/process limits in Basic (level-dependent capabilities).
- **Windows**: Job-Object memory limits (256 MB process / 512 MB job, kill-on-close) only; no filesystem/network/child allowlists.

### Strict semantics (Phase 46, legacy adapter; Phase 89: filesystem-only)

- **Landlock**: read/write allowlists enforced; `denied_paths` are typed `Unsupported` (fail closed); no network/process/child limits. The legacy `ProcessSandbox`/Landlock path never installs the jail seccomp filter — syscall-filter confinement comes only through an explicit guarantee request (`NetworkDenied` / `ChildCreationDenied` / `ExecDenied` → `PreparedSandbox::enter`).
- **Pledge**: unveil `r` / `rwc` allowlists + empty-perm denies + `pledge("stdio")` (denies inet/proc/exec).
- **Seatbelt**: `(deny default)` + `(allow process*)` + `(allow signal)` + explicit file allows + explicit denies + explicit `(deny network*)`; **no** `(allow job-creation)` so child creation stays denied. No numeric resource limits (`process_limits: false`). `(allow process*)` is retained as the minimal lifecycle primitive pending native minimization — do not narrow further without proving the jail still runs. The old Basic profile's contradictory `(allow default)` + `(deny default)` pair is removed; the old `(allow process)` (bare, no wildcard) was an unbound variable caught by native `sandbox_init` failure and is now `(allow process*)`.
- **Capsicum / Windows**: cannot enforce Strict (no read allowlist) — Strict fails closed by design. Capsicum Basic gives capability mode; Windows Basic gives Job-Object limits.

## Backend capabilities (truthful)

### Linux (Landlock + seccomp)

Landlock provides filesystem path sandboxing via the maintained `landlock`
crate (0.4.7, ABI-9 surface; vetted ABI V1 allowlist). Availability = a live
Landlock ABI probe (real ruleset creation with `HardRequirement`), never
kernel-release text. Required restrictions use `HardRequirement`;
`RestrictionStatus` must read `FullyEnforced` + `no_new_privs`, verified
post-entry (`PR_GET_NO_NEW_PRIVS` in child tests). Rule fds are RAII-owned.
Explicit deny paths are typed `Unsupported` (fail closed — Landlock cannot
represent deny under an allowed ancestor).

A categorical seccomp layer (`seccompiler`, pure Rust, no system lib) is
selected per guarantee, never installed unconditionally with Landlock
(Phase 89 Finding B):
`NetworkDenied` → `socket`/`socketpair`/`connect` denial;
`ChildCreationDenied` → non-thread `clone` (+`fork`/`vfork` on x86_64) +
`clone3` (ENOSYS for transparent glibc fallback); `ExecDenied` →
`execve`/`execveat` (EPERM), via TSYNC/all-threads installed after startup
resources exist and before untrusted work. A request for only one category
never acquires unrelated restrictions. Thread creation (`CLONE_THREAD`)
keeps working for the Wasmtime/YARA runtimes (proven by child test + jail
round trips under the real filter). The denied set is hardcoded (never from
untrusted input); failure fails closed. `NetworkTcpRestricted` /
`NetworkUdpRestricted` alone are `Unsupported` on Linux (the filter cannot
distinguish TCP from UDP without broader denial; request `NetworkDenied`).
The final guarantee report is derived from installation receipts, never from
a compile probe alone.

**Capabilities (guarantee report):**
- Read path allowlist: Yes (read rules for read roots)
- Write path allowlist: Yes (read+write rules for write roots)
- Deny paths: No (typed unsupported, fail closed)
- Process limits: No
- Network restrictions: Yes **iff** `NetworkDenied` was requested and its seccomp category installed, else honestly unsupported
- Child process restrictions: Yes **iff** `ChildCreationDenied` was requested and its seccomp category installed (creation denied; descendants inherit the domain), else unsupported
- Exec denial: Yes **iff** `ExecDenied` was requested and its category installed

Jail lifecycle (Phase 89 Finding A): exactly one irreversible transition per
workload (`prepare_sandbox(jail_guarantee_request())?.enter()`, witness
retained through the serve loop). No legacy compatibility probe enters a
second sandbox. The jail request explicitly requires ambient-FS deny, read
allowlist, inherited-IPC usable, descendants confined, plus
no-network/no-child/no-exec. There is no `SandboxRequest::intersect()`
composition API (removed Phase 89 as unsafe policy algebra); request
construction is explicit at call sites.

### FreeBSD (Capsicum)

Capsicum provides capability-mode sandboxing at the syscall level. FD-based: no path allowlists. `is_supported` probes `cap_getmode` syscall presence (not "already in capability mode" — the old `mode != 0` check was backwards). Before `cap_enter`, stdio rights are narrowed with `cap_rights_limit` (stdin read, stdout/stderr write), accidental descriptors ≥3 are closed (`closefrom`), and `cap_getmode` verifies entry. **A raw pathname vector is not a Capsicum allowlist:** path-policy requests report unsupported (fail closed) until preopened directory capabilities land. Descendant confinement is reported as such — never as child-creation denial.

**Capabilities:**
- Read path allowlist: No (preopen required; path vectors unsupported)
- Write path allowlist: No
- Deny paths: No
- Process limits: No (capability confinement is not a numeric memory/CPU limit)
- Network restrictions: Yes (capability-mode global-namespace restriction)
- Child process restrictions: Descendants confined yes; creation denial no

Strict requires a read allowlist, so Strict on Capsicum always fails closed.

### OpenBSD (Pledge/Unveil)

OpenBSD uses `pledge(2)` for syscall restrictions and `unveil(2)` for filesystem path restrictions (`r` / `rwc` / empty-perm deny). Paths cross the boundary as OS-native bytes (never lossy `display()`; interior NUL rejected, empty rejected); unveil is locked (`unveil(NULL,NULL)`, fail-closed) before the minimal `stdio` pledge, which omits `inet`/`proc`/`exec` (network, child creation, and exec denied rather than inherited). `prot_exec` is never added casually (Wasmtime/JIT needs on OpenBSD stay a backend-specific requirement proven by native workload tests).

**Capabilities:**
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: Yes
- Process limits: No (syscall filtering is not a numeric limit)
- Network restrictions: Yes (`pledge("stdio")` denies inet)
- Child process restrictions: Yes (`pledge("stdio")` denies proc/exec)

### macOS (Seatbelt) — experimental, deprecated API

Seatbelt here is the CLI/jail `sandbox_init` interface, which Apple has deprecated. It is **not** Apple App Sandbox (entitlements/signed bundles). For a CLI daemon/jail helper, moving to App Sandbox would be an architectural/distribution change, not a drop-in API migration. Long-term options: (1) retain deprecated Seatbelt as opt-in experimental hardening with native tests; (2) ship signed sandboxed helpers with entitlements if distribution supports it; (3) keep Linux as the strict-isolation production recommendation with macOS as development/experimental. Current choice: (1) + (3).

Requires the `macos-sandbox` Cargo feature **and** a runtime `sandbox_init` symbol (probed via `dlsym`). Without both, all capabilities are false and Strict fails closed. FFI passes a real error buffer, converts via `sandbox_free_error` (errno fallback only when the API provides no message).

SBPL path safety: paths are canonicalized when possible (symlink-resolved; falls back to the original when missing) and escaped as double-quoted literals (backslash/quote escaped; controls and non-UTF-8 rejected). Never interpolates `Path::display()` directly. A `)` inside a quoted literal cannot gain an extra expression.

**Capabilities when `macos-sandbox` enabled (level-dependent):**

Strict:
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: Yes
- Process limits: No (SBPL sets no numeric bounds)
- Network restrictions: Yes (explicit `deny network*` + deny default)
- Child process restrictions: Yes (no `job-creation` allow; creation denied by default)

Basic: read/write/deny Yes; process/network/child No (allow-default permissive).

**Without `macos-sandbox` feature:** All capabilities are false; sandboxing is not enforced; Strict fails closed.

### Windows (Job Objects) — limited

Windows "sandboxing" is process-level resource limiting via Job Objects (256 MB process / 512 MB job, kill-on-close — generated ABI, class 9 extended limits, query-verified) plus DEP/ASLR mitigations via the documented structures (Strict path; already-enforced reported honestly, never as newly applied). Nested-job assignment failure is a typed conflict, never "limits installed". The Job handle is owned for the confinement lifetime (retained via the sandbox guard; dropping is loud by design). **Host-global DACL mutation was removed from sandbox semantics** (it changes filesystem objects for all processes — never a process-local allowlist; a future filesystem-hardening API would own it separately).

Job Objects constrain a process tree; they are **not** an access-control sandbox (no AppContainer in this campaign — explicit gate decision, see the closeout). There is no deny-by-default for the rest of the filesystem, no network restriction, and no child-process restriction.

**Capabilities (all levels):**
- Read path allowlist: No
- Write path allowlist: No
- Deny paths: No
- Process limits: Yes
- Network restrictions: No
- Child process restrictions: No

Strict requires a read allowlist, so Strict on Windows always fails closed. Jail `Required` isolation on Windows fails closed unless the test-only `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch is set (production spawn paths never set it).

## Configuration

```toml
[worker]
sandbox_level = "strict"  # off, basic, or strict
sandbox_read_paths = ["/var/lib/synvoid", "/etc/synvoid"]
sandbox_write_paths = ["/var/lib/synvoid", "/var/log/synvoid"]
sandbox_no_access_paths = ["/etc/passwd", "/etc/shadow"]
```

## Usage Example

```rust
use synvoid_platform::sandbox::{
    EnteredSandbox, Guarantee, SandboxRequest, ThreadScope, prepare_sandbox,
};

// New production code: explicit guarantees, not adjectives.
let request = SandboxRequest::new()
    .require(Guarantee::AmbientFilesystemDenied)
    .require(Guarantee::FilesystemReadAllowlist)
    .require(Guarantee::InheritedIpcUsable)
    .scope(ThreadScope::CurrentThreadPlusDescendants)
    .read_path("/var/lib/synvoid");
let prepared = prepare_sandbox(request)?; // validate + probe, no side effects
let entered: EnteredSandbox = prepared.enter()?; // irreversible; retain through work
```

Legacy adapter (pinned compat only — do not use for new decisions):

```rust
use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

let sandbox = ProcessSandbox::with_paths(SandboxLevel::Strict, paths)?;
```

## Security Notes

- New production code requests explicit guarantees; a required guarantee that
  is unsupported/degraded aborts before untrusted work (`EnforcementReport::require_all`)
- A strict sandbox requires a backend with `read_path_allowlist` capability (legacy adapter)
- If the backend cannot enforce strict mode, `ProcessSandbox::with_paths()` returns `SandboxError::InsufficientCapabilities`
- Path allowlists use directory inheritance (subpath access is granted if parent is allowed)
- On Linux, explicit deny paths are typed `Unsupported` (fail closed — Landlock cannot represent them)
- Child-creation denial and descendant confinement are distinct guarantees (never conflated)
- Resource limits are distinct from access-control isolation
- On macOS, canonicalize temp paths (`/var` → `/private/var`) before comparing allowlists in tests; the backend canonicalizes automatically
- Never claim Apple App Sandbox equivalence for the `sandbox_init` backend
- Historical Phase 46/48 backend evidence is superseded by the Phases 81–84 corrective (`architecture/process_sandbox_corrective_closeout.md`); extraction is DEFERRED (no standalone crate)
