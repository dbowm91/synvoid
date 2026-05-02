# Sandbox Hardening - Priority 5

## Overview

The sandbox abstraction in `src/platform/sandbox.rs` provides a common interface for OS-level sandboxing across platforms. However, implementations differ dramatically from the abstraction contract.

## Issues Found

### 1. `SandboxPaths::write_paths()` Not Used

**Location**: `src/platform/sandbox.rs:138-151`

```rust
pub fn with_paths(level: SandboxLevel, paths: SandboxPaths) -> Result<Self, SandboxError> {
    // ...
    let read_refs: Vec<&Path> = paths.read_paths.iter().map(|p| p.as_path()).collect();
    let denied_refs: Vec<&Path> = paths.no_access_paths.iter().map(|p| p.as_path()).collect();

    sandbox.backend.apply(&read_refs, &denied_refs)?;  // write_paths is ignored!
    // ...
}
```

**Problem**: `SandboxPaths` has separate `read_paths` and `write_paths` vectors, but `with_paths()` only passes `read_paths` and `no_access_paths`. The `write_paths()` getter is never called.

**Impact**: Write access is either granted to read paths or not distinguished at all, depending on the backend.

---

### 2. Linux Landlock Hardcoded Access Masks

**Location**: `src/platform/sandbox.rs:248-256` and `src/platform/sandbox.rs:342-344`

```rust
// Hardcoded in create_landlock_ruleset()
let attr = LandlockRulesetAttr {
    handled_access_fs: 0b111,  // Read + Write + Execute - too broad
};

// Hardcoded per-path in apply()
for path in allowed_paths {
    let access = 0b11;  // Read + Write only, still hardcoded
    self.add_path_rule(ruleset_fd, path, access)?;
}
```

**Problem**: Landlock access rights are hardcoded as:
- `0b111` (7) for ruleset - allows read, write, and execute
- `0b11` (3) per path - allows read and write

**What the mask means**:
- `0b001` = read
- `0b010` = write
- `0b100` = execute

**Fix needed**: Use named constants like `LANDLOCK_ACCESS_FS_READ`, `LANDLOCK_ACCESS_FS_WRITE` from the kernel headers, and distinguish between read-only and read-write paths.

---

### 3. FreeBSD `cap_enter()` Called During Availability Check

**Location**: `src/platform/sandbox.rs:395-401`

```rust
fn is_capsicum_available() -> bool {
    unsafe {
        libc::cap_enter();  // PROBLEM: This enters the sandbox!
        let enabled = libc::cap_getmode(std::ptr::null_mut());
        enabled >= 0
    }
}
```

**Problem**: `is_capsicum_available()` calls `cap_enter()` before checking `cap_getmode()`. Calling `cap_enter()` **actually enters the capability mode** - it's not a simulation. Once entered, the process can only use file descriptors it explicitly holds.

**Impact**: Calling `is_supported()` or any method that checks availability would **prematurely enter the sandbox**, potentially breaking subsequent operations that need broader access.

**Fix**: Check `cap_getmode()` first without calling `cap_enter()`. The availability check should only query the system capability, not activate it.

---

### 4. macOS `is_supported()` Returns True When Feature Disabled

**Location**: `src/platform/sandbox.rs:806-808`

```rust
fn is_supported() -> bool {
    true  // Always returns true, ignores feature flag
}
```

**Problem**: `is_supported()` unconditionally returns `true`, even when the `macos-sandbox` feature is not enabled. The actual sandbox enforcement is gated behind `#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]`, but the support check doesn't reflect this.

**Impact**: Users may think seatbelt is available and supported when it's actually disabled.

**Fix**: `is_supported()` should check the feature flag:
```rust
fn is_supported() -> bool {
    cfg!(feature = "macos-sandbox")
}
```

---

### 5. Windows Job Objects Are Process Limits, Not Filesystem Sandboxing

**Location**: `src/platform/sandbox.rs:592-711`

```rust
fn apply_job_object(&self) -> Result<(), SandboxError> {
    // Sets memory limits, process limits, kill-on-close
    // But does NOT restrict filesystem access
}

impl SandboxBackend for WindowsSandbox {
    fn apply(
        &self,
        allowed_paths: &[&Path],   // IGNORED
        denied_paths: &[&Path],    // IGNORED
    ) -> Result<(), SandboxError> {
        // ...
        // allowed_paths and denied_paths are never used
    }
}
```

**Problem**: Windows Job Objects provide:
- Memory limits (process memory, job memory)
- Process count limits
- CPU priority/scheduling limits
- Kill process when job closes

Job Objects do **NOT** provide filesystem path restrictions. The `allowed_paths` and `denied_paths` parameters are accepted but completely ignored.

**Impact**: On Windows, the sandbox does not actually restrict filesystem access despite accepting path parameters.

**Documentation**: Windows Job Objects should be documented as "process resource controls" not "filesystem sandboxing". The abstraction contract implies filesystem isolation, which Windows cannot provide without third-party tools.

---

## Summary of Required Fixes

| Issue | Severity | Fix |
|-------|----------|-----|
| `write_paths()` ignored | High | Pass write paths separately to backends, or merge with read_paths based on backend capability |
| Landlock hardcoded masks | Medium | Use named constants; distinguish read-only vs read-write paths |
| FreeBSD `cap_enter()` in check | Critical | Check `cap_getmode()` first; remove `cap_enter()` from availability check |
| macOS `is_supported()` always true | Medium | Return `cfg!(feature = "macos-sandbox")` |
| Windows ignores path parameters | Low (docs) | Document that Windows Job Objects are process limits, not filesystem sandbox |

## Architecture Recommendation

The `SandboxBackend::apply()` signature should be reworked to explicitly handle read/write path distinction, or `SandboxPaths` should be passed directly so backends can extract what they need:

```rust
// Option 1: Explicit read/write separation
fn apply(&self, read_paths: &[&Path], write_paths: &[&Path], denied_paths: &[&Path]) -> Result<(), SandboxError>;

// Option 2: Pass SandboxPaths directly
fn apply(&self, paths: &SandboxPaths) -> Result<(), SandboxError>;
```

Option 2 is preferred as it allows backends to extract fields they support and ignore others.