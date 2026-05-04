# Sandboxing Guide

MaluWAF uses OS-level sandboxing to limit the damage potential of a compromised process. The sandbox restricts what resources (files, network, process creation) a compromised worker process can access.

## Supported Platforms

| Platform | Backend | Min Requirements |
|----------|---------|------------------|
| Linux | Landlock | Kernel 5.13+ |
| FreeBSD | Capsicum | FreeBSD 10+ with capsicum(4) |
| OpenBSD | Pledge/Unveil | OpenBSD 5.9+ |
| macOS | Seatbelt | macOS 10.10+ with `macos-sandbox` feature |
| Windows | Job Objects | Windows Vista+ (process-level only) |

## Sandbox Levels

| Level | Description |
|-------|-------------|
| `Off` | No sandboxing applied |
| `Basic` | Minimal restrictions, allows default actions |
| `Strict` | Full restrictions via read-path allowlist |

## Backend Capabilities

### Linux (Landlock)

Landlock provides filesystem path sandboxing by creating a ruleset of allowed file access patterns.

**Capabilities:**
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: No (use no-access paths as workaround)
- Process limits: No
- Network restrictions: No
- Child process restrictions: No

### FreeBSD (Capsicum)

Capsicum provides capability mode sandboxing at the syscall level. Capsicum is checked via `cap_getmode()` and must be explicitly enabled on the system.

**Important:** `cap_enter()` permanently enters capability mode. The `is_capsicum_available()` check only queries whether the system supports capsicum mode (via `cap_getmode()`), it does NOT enter the sandbox.

**Capabilities:**
- Read path allowlist: No (capsicum is FD-based)
- Write path allowlist: No
- Deny paths: No
- Process limits: Yes
- Network restrictions: Yes
- Child process restrictions: Yes

### OpenBSD (Pledge/Unveil)

OpenBSD uses `pledge(2)` for syscall restrictions and `unveil(2)` for filesystem path restrictions.

**Capabilities:**
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: Yes
- Process limits: Yes
- Network restrictions: Yes
- Child process restrictions: Yes

### macOS (Seatbelt)

Seatbelt provides sandboxing via a policy language. Requires the `macos-sandbox` feature flag.

**Capabilities (when `macos-sandbox` enabled):**
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: Yes
- Process limits: Yes
- Network restrictions: Yes
- Child process restrictions: Yes

**Without `macos-sandbox` feature:** All capabilities are false; sandboxing is not enforced.

### Windows (Job Objects)

Windows "sandboxing" is process-level resource limiting via Job Objects. This provides memory limits and kill-on-job-close semantics, but **does NOT provide filesystem path sandboxing, network restrictions, or child process restrictions**.

Path sandboxing on Windows would require separate mechanisms like AppContainer or DACLs, which are not implemented here.

**Capabilities:**
- Read path allowlist: No
- Write path allowlist: No
- Deny paths: No
- Process limits: Yes
- Network restrictions: No
- Child process restrictions: No

## Configuration

```toml
[worker]
sandbox_level = "strict"  # off, basic, or strict
sandbox_read_paths = ["/var/lib/maluwaf", "/etc/maluwaf"]
sandbox_write_paths = ["/var/lib/maluwaf", "/var/log/maluwaf"]
sandbox_no_access_paths = ["/etc/passwd", "/etc/shadow"]
```

## Usage Example

```rust
use crate::platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

let paths = SandboxPaths::new()
    .add_read_path("/var/lib/maluwaf")
    .add_write_path("/var/log/maluwaf");

let sandbox = ProcessSandbox::with_paths(SandboxLevel::Strict, paths)?;
```

## Security Notes

- A strict sandbox requires a backend with `read_path_allowlist` capability
- If the backend cannot enforce strict mode, `ProcessSandbox::with_paths()` returns `SandboxError::InsufficientCapabilities`
- Path allowlists use directory inheritance (subpath access is granted if parent is allowed)
- On Linux, denied paths are logged but cannot be fully blocked with Landlock
