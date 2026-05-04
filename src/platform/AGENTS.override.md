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
| `crates/maluwaf-utils/src/buffer/pool.rs` | Custom buffer pool (sharded mutex + TLS cache) |

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

The buffer pool (`crates/maluwaf-utils/src/buffer/pool.rs`) uses:
- **Sharded Mutex**: 8 shards with `parking_lot::Mutex<Vec<BytesMut>>` per tier. **Eliminates ABA vulnerability** that existed in the old TreiberStack design.
- **ThreadLocalCache**: Uses `RefCell` for safe interior mutability (thread-local guarantees single-threaded access).

The module has `#[deny(unsafe_code)]` - no unsafe blocks remain.

### 5. Operation-Specific Privilege Checks

Firewall operations use operation-specific privilege checks instead of a single `is_admin()`:

```rust
can_load_ebpf()           // Checks unprivileged_bpf_disabled state
can_modify_nftables()     // Linux-only, checks root or CAP_NET_ADMIN
can_modify_firewall()     // Generic admin check for Windows
```

Filter backends expose state via `FilterState`:
- `InactiveNotPrivileged` - Backend inactive due to permissions
- `InactiveConfigError` - Backend inactive due to config issues
- `Active` - Backend is operational

### 6. Socket Path Security

Socket directories are created with:
- `0o700` permissions
- Ownership verification (current UID or root)
- Symlink rejection via `symlink_metadata()`
- Per-UID isolation via `get_user_socket_dir()` returning `/tmp/maluwaf-{uid}`

### 7. Lock File Acquisition

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

- FreeBSD Capsicum: `is_capsicum_available()` checks `cap_getmode()` first - does not call `cap_enter()` unless sandbox is explicitly applied
- macOS Seatbelt: Requires `macos-sandbox` feature flag to actually enforce
- Windows sandbox: Filesystem restrictions NOT enforced (only process limits)
- Non-Unix platforms: Socket FD passing not supported, returns `NotSupported`