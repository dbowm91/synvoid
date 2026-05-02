# Platform/Systems Layer - AGENTS.override.md

This module covers foundational systems code including IPC, process management, platform abstraction, sandboxing, and buffer pools.

## Key Modules

| Module | Purpose |
|--------|---------|
| `src/platform/mod.rs` | Platform enum, capability queries, re-exports |
| `src/platform/sandbox.rs` | OS sandboxing backends (Landlock, Capsicum, Pledge, Seatbelt, Job Objects) |
| `src/platform/ipc.rs` | Platform IPC trait abstraction |
| `src/platform/unix.rs` | Unix platform implementations |
| `src/platform/windows_impl.rs` | Windows platform implementations |
| `src/process/ipc.rs` | Main IPC message protocol (1889 lines) |
| `src/process/ipc_signed.rs` | Signed IPC framing with replay protection |
| `src/process/ipc_transport.rs` | Async IPC transport layer |
| `src/process/socket_path.rs` | Secure socket directory management |
| `src/process/pidfile.rs` | PID file and lock file management |
| `crates/maluwaf-utils/src/buffer/pool.rs` | Custom buffer pool (lock-free + TLS cache) |

## Critical Patterns

### 1. Platform-Gated Imports

Many imports are platform-specific. Always use `#[cfg(unix)]` or `#[cfg(windows)]` guards:

```rust
#[cfg(unix)]
use nix::fcntl::{flock, FlockArg};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
```

### 2. SandboxCapabilities

Each sandbox backend reports its actual capabilities honestly via `SandboxCapabilities`:

```rust
pub struct SandboxCapabilities {
    pub read_path_allowlist: bool,
    pub write_path_allowlist: bool,
    pub deny_paths: bool,
    pub process_limits: bool,
    pub network_restrictions: bool,
    pub child_process_restrictions: bool,
}
```

**Important**: Windows Job Objects only enforce process limits, NOT filesystem restrictions. Use `ProcessSandbox::capabilities()` to check.

### 3. IPC Signing

All privileged IPC (Stop, ReloadConfig) requires signed messages. Use `IpcSigner` for HMAC-SHA3-256 verification with 60-second replay protection.

Key files:
- `src/process/ipc_signed.rs` — signed framing
- `src/process/ipc_framing.rs` — unsigned framing

### 4. Buffer Pool Safety

The buffer pool (`crates/maluwaf-utils/src/buffer/pool.rs`) currently uses:
- **TreiberStack**: Lock-free stack with CAS. **CRITICAL**: Vulnerable to ABA problem under high contention.
- **ThreadLocalCache**: Uses `RefCell` for safe interior mutability (thread-local guarantees single-threaded access).

**Planned Refactor**: Replace `TreiberStack` with a sharded mutex-backed `Vec<BytesMut>` to eliminate ABA vulnerability and remove `unsafe` code.

**Safety Note**: Current `unsafe` blocks in `pool.rs` lack proper `SAFETY` documentation. Always verify invariants before modifying.

### 5. Socket Path Security

Socket directories are created with:
- `0o700` permissions
- Ownership verification (current UID or root)
- Symlink rejection via `symlink_metadata()`
- **Planned**: Per-UID isolation in `/tmp/maluwaf-{uid}` (pending implementation)

### 6. Lock File Acquisition

`OverseerLockFile` acquires `flock` BEFORE writing to avoid truncation races:
1. Open without truncate
2. Acquire exclusive lock
3. Write content under lock

## Hot Path Considerations

- IPC framing is optimized for control-plane traffic (1 MiB max message size)
- Buffer pool acquisition is O(1) via TLS cache
- Socket path lookups use generation counters for zero-downtime upgrades

## Verification Commands

```bash
cargo test --lib process
cargo test --lib platform
cargo test --lib buffer
cargo test --test ipc_test
cargo fmt && cargo clippy --lib -- -D warnings
```

## Known Limitations

- FreeBSD Capsicum: `cap_enter()` permanently enters capability mode - `is_supported()` just returns `true` without calling it
- macOS Seatbelt: Requires `macos-sandbox` feature flag to actually enforce
- Windows sandbox: Filesystem restrictions NOT enforced (only process limits)
- Non-Unix platforms: Socket FD passing not supported, returns `NotSupported`