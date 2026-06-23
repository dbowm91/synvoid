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
    fn apply(&self, allowed_paths: &[&Path], denied_paths: &[&Path]) -> Result<(), SandboxError>;
    fn is_supported(&self) -> bool;
    fn feature_name(&self) -> &'static str;
    fn level(&self) -> SandboxLevel;
}
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

**Location**: `src/platform/sandbox.rs:610-785`

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

macOS uses the Sandbox framework with policy profiles.

### Implementation

**Location**: `src/platform/sandbox.rs:787-911`

```rust
pub struct SeatbeltSandbox {
    level: SandboxLevel,
}

impl SeatbeltSandbox {
    fn compile_sandbox_profile(
        allowed_paths: &[&Path],
        denied_paths: &[&Path],
        level: SandboxLevel,
    ) -> String {
        let mut profile = String::new();
        profile.push_str("(version 1)\n");

        match level {
            SandboxLevel::Basic => {
                profile.push_str("(allow default)\n");
                profile.push_str("(deny default)\n");
            }
            SandboxLevel::Strict => {
                profile.push_str("(deny default)\n");
                profile.push_str("(allow process)\n");
                profile.push_str("(allow signal)\n");
                profile.push_str("(allow job-creation)\n");
            }
            SandboxLevel::Off => {
                profile.push_str("(allow default)\n");
                return profile;
            }
        }

        // Add path rules
        for path in allowed_paths {
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                path.display()
            ));
        }

        profile
    }
}
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

Enable with: `macos-sandbox = ["dep:synvoid/macos-sandbox"]`

## Linux Landlock

Linux uses the Landlock LSM for filesystem restrictions.

### Implementation

**Location**: `src/platform/sandbox.rs:199-620`

Key steps:
1. Create ruleset with `SYS_landlock_create_ruleset`
2. Add path rules with `SYS_landlock_add_rule`
3. Restrict self with `SYS_landlock_restrict_self`

## FreeBSD Capsicum

Capsicum provides capability mode for FreeBSD.

### Implementation

**Location**: `src/platform/sandbox.rs:323-467`

Key operations:
- `cap_enter()` - Enter capability mode
- `cap_rights_limit()` - Restrict file descriptor rights

## OpenBSD Pledge

Pledge provides system call filtering on OpenBSD.

### Implementation

**Location**: `src/platform/sandbox.rs:469-611`

Key operations:
- `pledge()` - Promise minimal syscall access
- `unveil()` - Restrict filesystem visibility

## SandboxPaths Builder

Use `SandboxPaths` to configure allowed/denied paths:

```rust
use crate::platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

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
