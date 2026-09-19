# Platform/Systems Layer - AGENTS.override.md

This module covers foundational systems code including IPC, process management, platform abstraction, sandboxing, and buffer pools.

## Canonical paths (Phase 32)

`crates/synvoid-platform` is the single compiled owner of OS/platform
primitives. `src/platform/` is a pure re-export facade (`mod.rs` only: module
aliases + historical top-level names, no implementations — enforced by
`tests/platform_canonicalization_guard.rs`). Implement in the crate, import
`synvoid_platform` directly (including from root internals).

## Key Modules

| Module | Purpose |
|--------|---------|
| `crates/synvoid-platform/src/lib.rs` | Platform enum, capability queries, module wiring |
| `crates/synvoid-platform/src/sandbox.rs` | OS sandboxing backends (Landlock, Capsicum, Pledge, Seatbelt, Job Objects) |
| `crates/synvoid-platform/src/ipc.rs` | Platform IPC trait abstraction |
| `crates/synvoid-platform/src/process.rs` | Signal enum, process control/signal traits, `terminate_process` |
| `crates/synvoid-platform/src/socket.rs` | Socket traits, owned types, handoff helpers |
| `crates/synvoid-platform/src/socket_bind.rs` | Canonical `bind_tcp_reuse` / `bind_udp_reuse` |
| `crates/synvoid-platform/src/service/` | Service management (systemd, rc.d, `sc.exe`) |
| `crates/synvoid-platform/src/fs.rs` | `SecureDir`, `PlatformPaths` (`new` = SynVoid layout, `for_app` = app-neutral) |
| `crates/synvoid-platform/src/unix.rs` | Unix backends (private module; `Platform*` aliases are the API) |
| `crates/synvoid-platform/src/windows_impl.rs` | Windows backends (private module) |
| `crates/synvoid-platform/src/windows/` | Windows operator helpers (firewall, interface resolver, Wintun) |
| `crates/synvoid-ipc/src/ipc.rs` | Main IPC message protocol (1889 lines) |
| `crates/synvoid-ipc/src/ipc_signed.rs` | Signed IPC framing with replay protection |
| `crates/synvoid-ipc/src/ipc_transport.rs` | Async IPC transport layer |
| `crates/synvoid-ipc/src/socket_path.rs` | Secure socket directory management |
| `crates/synvoid-ipc/src/pidfile.rs` | PID file and lock file management |
| `crates/synvoid-utils/src/buffer/pool.rs` | Custom buffer pool (sharded mutex + TLS cache) |

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
- `crates/synvoid-ipc/src/ipc_signed.rs` — signed framing
- `crates/synvoid-ipc/src/ipc_framing.rs` — unsigned framing

### 4. Buffer Pool Safety

The buffer pool (`crates/synvoid-utils/src/buffer/pool.rs`) uses:
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
- Per-UID isolation via `get_user_socket_dir()` returning `/tmp/synvoid-{uid}`

### 7. Lock File Acquisition

`OverseerLockFile` acquires `flock` BEFORE writing to avoid truncation races:
1. Open without truncate
2. Acquire exclusive lock
3. Write content under lock

### 8. Application-neutral paths

`PlatformPaths::new()` returns the exact historical SynVoid layout (do not
change deployment paths). New embedders use `PlatformPaths::for_app(id)`,
which validates the id (`validate_app_id`: `[A-Za-z0-9._-]`, non-empty,
≤64 bytes, not `.`/`..`) and substitutes it into the per-platform layout.
`PlatformError::InvalidAppId` is the rejection signal.

## Hot Path Considerations

- IPC framing is optimized for control-plane traffic (1 MiB max message size)
- Buffer pool acquisition is O(1) via TLS cache
- Socket path lookups use generation counters for zero-downtime upgrades

## Verification Commands

```bash
cargo test -p synvoid-platform --profile ci
cargo test --test platform_canonicalization_guard --profile ci
cargo test --test ipc_test
cargo fmt && cargo clippy -p synvoid-platform --all-targets -- -D warnings
```

### 9. TUN Device Administration Check

`Platform::is_admin_required_for_tun()` at `crates/synvoid-platform/src/lib.rs`
correctly returns:
- `false` for Unix platforms (Linux, macOS, BSD)
- `true` for Windows and Unknown platforms

This is intentional - Unix platforms use `CAP_NET_ADMIN` capability which doesn't require root. TUN operations work because `can_modify_nftables()` correctly uses capability checks.

## Dependency policy (Phase 32, Part C)

- OS syscall wrappers own target-scoped deps in `crates/synvoid-platform/Cargo.toml`:
  `nix` + `daemonize2` (unix), `tokio` `rt`+`signal` (unix/Windows signal
  listeners), `windows-sys` + `libloading` + `zip` (Windows), `synvoid-utils`
  (`RunningFlag`; acyclic — utils never depends on platform).
- No `synvoid-metrics`, `synvoid-config`, root `synvoid`, or `synvoid-ipc`
  edges from the platform crate — not even dev-dependencies.

## Known Limitations

- FreeBSD Capsicum: `is_capsicum_available()` probes `cap_getmode` syscall presence (availability, not "already sandboxed"; the old `mode != 0` check was backwards) - does not call `cap_enter()` unless sandbox is explicitly applied. FD-based only: no path allowlists, Strict fails closed. Note: `limit_fd()` method was **removed** - it was dead code never called in `apply()`.
- macOS Seatbelt (Phase 46 experimental, deprecated `sandbox_init`, not App Sandbox): implemented in `crates/synvoid-platform/src/sandbox.rs`; requires `macos-sandbox` feature AND runtime symbol, Basic allow-default / Strict deny-default with explicit network deny and no job-creation allow, SBPL paths escaped/canonicalized, FFI error buffer freed via `sandbox_free_error`. Native child-process tests in `tests/sandbox_macos_enforcement.rs`. Linux is the production recommendation for strict isolation.
- Windows sandbox (limited): Filesystem/network/child allowlists NOT enforced (all path capabilities false; Strict fails closed). Only Job-Object numeric limits (256 MB proc / 512 MB job, kill-on-close). DACL touches are hardening, not allowlists. DEP/ASLR mitigation via `SetProcessMitigationPolicy`.
- Non-Unix platforms: Socket FD passing not supported, returns `NotSupported`
