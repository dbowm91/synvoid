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

Windows uses Job Objects for process containment with memory limits and automatic cleanup.

### Implementation

**Location**: `crates/synvoid-platform/src/sandbox.rs`

```rust
pub struct WindowsSandbox {
    level: SandboxLevel,
    applied: AtomicBool,
}

impl WindowsSandbox {
    fn apply_job_object(&self) -> Result<(), SandboxError> {
        // Create Job Object with memory limits
        let job = unsafe {
            windows_sys::Win32::System::Threading::CreateJobObjectW(
                Some(std::ptr::null_mut()),
                Some(std::ptr::null_mut()),
            )
        };

        // Configure limits: 256MB process, 512MB job, kill on close
        let mut limit_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION_T {
                limits_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                    | JOB_OBJECT_LIMIT_JOB_MEMORY,
                process_memory_limit: 256 * 1024 * 1024,
                job_memory_limit: 512 * 1024 * 1024,
                ..Default::default()
            },
            ..Default::default()
        };

        // Apply limits to job
        windows_sys::Win32::System::Threading::SetInformationJobObject(
            job,
            JOBOBJECT_BASIC_LIMIT_INFORMATION,
            &mut limit_info,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        // Assign current process to job
        let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
        windows_sys::Win32::System::Threading::AssignProcessToJobObject(job, current_process);

        Ok(())
    }

    fn apply_mitigation_policies(&self) -> Result<(), SandboxError> {
        // Enable DEP and ASLR in Strict mode
        if self.level == SandboxLevel::Strict {
            SetProcessDEPPolicy(...);
            SetProcessASLRPolicy(...);
        }
        Ok(())
    }
}
```

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

Linux uses the Landlock LSM for filesystem restrictions.

### Implementation

**Location**: `crates/synvoid-platform/src/sandbox.rs`

Key steps (Phase 46: availability = kernel ≥5.13 AND live `landlock_create_ruleset` probe, not version text alone):
1. Create ruleset with `SYS_landlock_create_ruleset`
2. Add path rules with `SYS_landlock_add_rule`
3. Restrict self with `SYS_landlock_restrict_self`
Deny paths are logged, not enforced. No network/process/child limits.

## FreeBSD Capsicum

Capsicum provides capability mode for FreeBSD.

### Implementation

**Location**: `crates/synvoid-platform/src/sandbox.rs`

Key operations (Phase 46: no path allowlists; Strict fails closed):
- `cap_getmode()` presence probe = availability (not "already sandboxed")
- `cap_enter()` - Enter capability mode (irreversible)

## OpenBSD Pledge

Pledge provides system call filtering on OpenBSD.

### Implementation

**Location**: `crates/synvoid-platform/src/sandbox.rs`

Key operations:
- `pledge()` - Promise minimal syscall access
- `unveil()` - Restrict filesystem visibility

## SandboxPaths Builder

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

## Error Handling

```rust
pub enum SandboxError {
    #[error("Platform not supported: {0}")]
    NotSupported(String),
    #[error("Landlock not available (kernel < 5.13)")]
    LandlockUnavailable,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Syscall failed: {0}")]
    Syscall(String),
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
