---
name: sandboxing
description: OS sandboxing patterns for process confinement on Windows, macOS, Linux, and BSD.
---

# OS Sandboxing Patterns

This skill documents the sandboxing implementations used in the SynVoid codebase for OS-level process confinement.

## Overview

SynVoid implements platform-specific sandboxing using available OS mechanisms:

| Platform | Mechanism | Module | Feature Flag |
|---------|-----------|--------|--------------|
| Linux | Landlock | `linux::LandlockSandbox` | (always available) |
| FreeBSD | Capsicum | `capsicum::CapsicumSandbox` | (always available) |
| OpenBSD | Pledge | `pledge::PledgeSandbox` | (always available) |
| Windows | Job Objects | `windows::WindowsSandbox` | (always available) |
| macOS | Seatbelt | `darwin::SeatbeltSandbox` | `macos-sandbox` |

## Core Trait

All sandbox implementations implement the `SandboxBackend` trait:

```rust
pub trait SandboxBackend: Send + Sync {
    fn apply(&self, read_paths: &[&Path], write_paths: &[&Path], denied_paths: &[&Path]) -> Result<(), SandboxError>;
    fn is_supported(&self) -> bool;
    fn feature_name(&self) -> &'static str;
    fn level(&self) -> SandboxLevel;
    fn capabilities(&self) -> SandboxCapabilities;
}

// Support tiers (Phase 46): Linux Landlock = Supported (production for strict
// isolation); FreeBSD Capsicum / OpenBSD Pledge / macOS Seatbelt =
// Experimental; Windows Job Objects = Limited (process limits only);
// Stub = Unavailable (Strict fails closed). macOS Seatbelt uses deprecated
// sandbox_init, not App Sandbox entitlements. process_limits = numeric bounds
// only. See docs/SANDBOXING.md for the binding matrix.
```

### SandboxLevels

```rust
pub enum SandboxLevel {
    Off,    // No restrictions
    Basic,  // Minimal restrictions, allow common operations
    Strict, // Maximum restrictions, deny by default
}
```

## Windows Job Objects

Windows uses Job Objects for process containment with memory limits and automatic cleanup. Canonical implementation: generated `windows-sys` `JobObjects`/`SystemServices` types (never handwritten ABI copies).

### Implementation (Phases 81–84 corrective)

**Location**: `crates/synvoid-platform/src/sandbox.rs` (`windows::WindowsSandbox`)

- Extended-limit information class **9** (`JobObjectExtendedLimitInformation`,
  not 2) with limit flags `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (0x100) |
  `JOB_OBJECT_LIMIT_JOB_MEMORY` (0x200) | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
  (0x2000); configured limits 256 MB process / 512 MB job (unchanged defaults).
- After `SetInformationJobObject`, query back with
  `QueryInformationJobObject` and verify effective flags/limits
  (`PartialEnforcement` on mismatch).
- `AssignProcessToJobObject` failure (e.g. incompatible outer job) returns
  typed `SandboxError::BackendConflict`, never "limits installed".
- Mitigations use the real `PROCESS_MITIGATION_DEP_POLICY` (Flags=1) /
  `PROCESS_MITIGATION_ASLR_POLICY` (Flags=0b111) structures (never
  creation-policy scalars); query-back distinguishes newly-applied from
  already-enforced.
- **No host-global DACL mutation** (removed — never a process-local allowlist).
- The Job handle is owned (`Mutex<Option<isize>>`, closed once on drop);
  retain the sandbox guard through the workload (dropping is loud by design
  under kill-on-close).
- Job Objects are resource/lifecycle containment, not access-control
  sandboxing (no AppContainer; `Required` fails closed for access guarantees).

### Windows API Features Used

- `CreateJobObjectW` - Create job object with security attributes
- `SetInformationJobObject` with `JobObjectExtendedLimitInformation` - Set memory limits
- `AssignProcessToJobObject` - Add process to job
- `SetProcessMitigationPolicy` - Enable DEP/ASLR

### Memory Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Process Memory | 256 MB | Single process allocation limit |
| Job Memory | 512 MB | Total job (all processes) limit |
| Kill on Close | Yes | Ensures cleanup when parent exits |

## macOS Seatbelt

macOS uses the deprecated `sandbox_init` CLI/jail interface (NOT Apple App Sandbox entitlements). Experimental opt-in; Linux is the production recommendation for strict isolation.

### Implementation

**Location**: `crates/synvoid-platform/src/sandbox.rs`

```rust
// Phase 46 truthful profile (see compile_sbpl_profile in sandbox.rs):
// Basic = (allow default) only — the old (allow)+(deny) default pair was
// contradictory and is removed.
// Strict = (deny default) + (allow process*) + (allow signal) +
// (deny network*), NO job-creation allow (children stay denied).
// Bare (allow process) was an unbound variable (native failure).
// Paths go through escape_sbpl_string_literal after
// canonicalize_sbpl_path; never interpolate Path::display() directly.
// FFI passes a real error buffer, converts via sandbox_free_error.
```

### Profile Syntax

```
(version 1)
(allow default)           ; Basic: allow common operations
(deny default)            ; Strict: deny by default

; Allow reading files under path
(allow file-read* (subpath "/var/log"))

; Deny access to path
(deny file-read* (subpath "/etc/shadow"))
```

### Feature Flag

The actual `sandbox_init` call requires linking against the Sandbox framework:

```rust
#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: libc::c_int,
        error: *mut *mut libc::c_char,
    ) -> libc::c_int;
}
```

Enable with: `macos-sandbox` feature AND runtime `sandbox_init` symbol (probed via `dlsym`). Without both, Strict fails closed. Level-dependent capabilities: Basic claims no network/child limits; Strict claims network+child, never numeric process limits.

## Linux Landlock

Linux uses the Landlock LSM for filesystem restrictions via the maintained
`landlock` crate (0.4.x), plus a categorical seccomp layer (`seccompiler`)
for the jail's no-network/no-child/no-exec needs.

### Implementation (Phases 81–84 corrective)

**Location**: `crates/synvoid-platform/src/sandbox.rs`
(`linux::LandlockSandbox`, `linux::seccomp`)

- Availability = live Landlock ABI probe (real ruleset creation with
  `HardRequirement`), never kernel-release text.
- Required filesystem restrictions use `CompatLevel::HardRequirement`
  (vetted ABI V1 allowlist); production inspects `RestrictionStatus` and
  rejects `PartiallyEnforced`/`NotEnforced` plus unverified `no_new_privs`
  (proven with `PR_GET_NO_NEW_PRIVS` in child tests). Rule fds are RAII-owned.
- Explicit deny paths are typed `Unsupported` (fail closed).
- Seccomp deny-list (default Allow, never a giant allowlist), Phase 89
  guarantee-selected (never installed unconditionally with Landlock):
  `NetworkDenied` → new network authority; `ChildCreationDenied` →
  non-thread `clone` (+`fork`/`vfork` on x86_64), `clone3` (ENOSYS for
  glibc fallback); `ExecDenied` → `execve`/`execveat` — EPERM, TSYNC,
  installed after startup resources exist and before untrusted work, exactly
  once via `PreparedSandbox::enter()` from the internal `MechanismPlan`.
  One category never acquires unrelated restrictions; `NetworkTcpRestricted`
  / `NetworkUdpRestricted` alone are unsupported on Linux. Thread creation
  keeps working (proven). Denied set is hardcoded. Final reports are
  receipt-backed, never compile-probe claims.
- Portable callers use the guarantee contract (`SandboxRequest` →
  `prepare_sandbox` → `enter` → `EnteredSandbox`); the jail requirement is
  `jail_guarantee_request()` (ambient-FS deny, read allowlist, inherited IPC,
  descendants confined, plus authoritative no-network/no-child/no-exec) with
  exactly one irreversible entry (no legacy `with_paths(Strict)` probe).
  `SandboxRequest::intersect()` was removed (Phase 89: unsafe algebra).
  Never gate new code on `can_enforce_strict()`.

## FreeBSD Capsicum

Capsicum provides capability mode for FreeBSD. Descriptor-capability based:
stdio rights are narrowed with `cap_rights_limit` before `cap_enter`,
accidental descriptors ≥3 are closed (`closefrom`), and `cap_getmode`
verifies entry.

### Implementation (Phase 83 corrective)

**Location**: `crates/synvoid-platform/src/sandbox.rs`

Key operations (Phase 46 + 83: no path allowlists; Strict fails closed):
- `cap_getmode()` presence probe = availability (not "already sandboxed")
- `cap_rights_limit()` on stdio + `closefrom(3)` hygiene
- `cap_enter()` - Enter capability mode (irreversible), verified with `cap_getmode()`
- Raw pathname vectors report unsupported (fail closed) until preopened
  directory capabilities land; descendant confinement is never reported as
  child-creation denial.

## OpenBSD Pledge

Pledge provides system call filtering on OpenBSD, with unveil locked and
minimal promises.

### Implementation (Phases 81–84 corrective)

**Location**: `crates/synvoid-platform/src/sandbox.rs`

Key operations:
- `unveil()` with OS-native path bytes (never lossy `display()`;
  interior NUL and empty paths rejected) — `r` / `rwc` / empty-perm deny
- `unveil(NULL, NULL)` lock after policy construction (fail-closed)
- `pledge("stdio")` — omits `inet`/`proc`/`exec` (network, child creation,
  and exec denied); no casual `prot_exec`

## SandboxPaths Builder (legacy adapter — pinned compat, not for new decisions)

Use `SandboxPaths` to configure allowed/denied paths:

```rust
use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

let sandbox = ProcessSandbox::with_paths(
    SandboxLevel::Strict,
    SandboxPaths::new()
        .add_read_path("/var/log")
        .add_write_path("/tmp")
        .add_no_access_path("/etc/shadow"),
)?;
```

New production code must use the guarantee contract instead
(`SandboxRequest` → `prepare_sandbox` → `enter` → `EnteredSandbox`; jail:
`jail_guarantee_request()`). Never add a new `can_enforce_strict()` gate.

## Error Handling (Phases 81–84: typed fail-closed vocabulary)

```rust
pub enum SandboxError {
    #[error("Platform not supported: {0}")]
    NotSupported(String),
    #[error("Landlock not available (kernel < 5.13 or syscall unavailable)")]
    LandlockUnavailable,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Syscall failed: {0}")]
    Syscall(String),
    #[error("Invalid sandbox path: {0}")]
    InvalidPath(String),
    #[error("Strict sandbox requested but backend cannot enforce it: {0}")]
    InsufficientCapabilities(String),
    // Phase 81–82 additions (all fail closed on required paths):
    // Unsupported (incl. Landlock explicit-deny, Capsicum path vectors),
    // BackendConflict (outer-job assignment), PartialEnforcement (Landlock
    // status, seccomp/query mismatch, cap-mode verify), InvalidPolicy
    // (validation incl. allow/deny conflict), EntryFailed (post-prepare).
}
```

## Best Practices

1. **Always handle errors gracefully** - Sandbox failures shouldn't crash the process
2. **Check `is_supported()` first** - Not all platforms support all features
3. **Use appropriate levels** - Basic for development, Strict for production
4. **Test on target platforms** - Sandboxing behavior varies across OS versions
5. **Enable incrementally** - Start with Basic, verify functionality, then Strict

## Sandbox Jail Processes (Phase 22, Phase 29 packaged)

The strict sandbox above confines the WASM/YARA jail children (dedicated
`synvoid-wasm-jail` / `synvoid-yara-jail` binaries from
`crates/synvoid-jail-runtime/`, legacy `synvoid --wasm-jail` /
`--yara-jail` flags remain only as forwarding shims; child entry in
`crates/synvoid-jail-runtime/src/sandbox_entry.rs`, backends canonical in
`crates/synvoid-platform/src/sandbox.rs`).
Full jail contract: `architecture/sandbox_jail_protocol.md`. Rules when
touching jail code:

- IPC uses parent-created anonymous stdio pipes established before spawn;
  never add post-sandbox bind/connect, and never add a connectable namespace.
- Jail logs go to stderr; stdout carries only length-delimited frames
  (a stdout log line corrupts the stream and forces a restart).
- No generic exec operation, no secrets/payloads in argv or env, digests
  re-verified in the child with constant-time comparison.
- `IsolationPolicy::Required` fails closed; never add silent in-process
  fallback to a required path. Production routing defaults to `InProcess`;
  adopt per call site with result-comparison tests.
- On unsupported platforms the child fails closed; the only bypass is the
  test-only `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch, which production spawn
  paths must never set (asserted by `tests/jail_isolation_guard.rs`).

**YARA validation placement (corrective pass)**: full `synvoid-yara` syntax
validation runs in-process in the supervisor composition root AFTER trust
admission (edge-local submit only, post role/size gates) — deliberately NOT
through the YARA jail, because no untrusted network/peer text reaches the
compiler (remote ingress is size/signature-gated, approval distributes text
without compiling). The jail remains the boundary for YARA *execution*
(scanning); do not add a validation IPC op unless a future audit proves remote
text can reach the compiler. Proof: `architecture/mesh.md` §13.
