# Systems-Layer CI and Regression Gates

**Status**: OPEN
**Last Updated**: 2026-05-02

## Overview

Most systems-layer regressions will not be caught by ordinary Linux unit tests. Cross-platform
compile errors, unsafe buffer issues, IPC auth bypasses, and sandbox degradation need targeted
gates.

## CI/Local Verification Commands

### Linux Default Features

```bash
cargo check
cargo test --lib
cargo fmt --check
cargo clippy --lib -- -D warnings
```

### Linux No-Default Features

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

### macOS No-Default Features

```bash
# Native compilation (no cross-compile)
cargo check --no-default-features --features mesh,dns
# With macOS sandbox enabled
cargo check --no-default-features --features mesh,dns,macos-sandbox
```

### Windows MSVC No-Default Features

```bash
# Using MSVC toolchain explicitly
cargo +stable check --no-default-features --features mesh,dns
# Or via cross-compile if using cross-rs
```

### Feature-Specific Checks

| Feature | Platform | Check Command |
|---------|----------|---------------|
| `socket-handoff` | Unix/Linux | `cargo check --features socket-handoff` |
| `macos-sandbox` | macOS | `cargo check --features macos-sandbox` (compile only, runtime requires sandbox entitlement) |
| `icmp-filter` | Linux | `cargo check --features icmp-filter` |
| Windows named pipes | Windows | `cargo check --features default` |

## Security Regression Tests

### IPC Unsigned Rejection Test Concept

**What it tests**: IPC messages without a valid signature are rejected.

The IPC layer uses `SignedIpcMessage` and `IpcSigner` (see `src/process/ipc_signed.rs`). Messages
that arrive without a signature or with an invalid signature should be rejected before processing.

**Test concept**:
1. Establish IPC connection between master and worker
2. Send a raw `MasterCommand` message without signing it
3. Verify the connection is closed or an error is logged
4. Send a message with an invalid signature
5. Verify rejection with error code

**Current state**: Signing verification happens in `src/process/ipc_signed.rs` - the test concept
should validate that `verify_signature` on `IpcSigner` properly rejects unsigned/invalid messages.

### Key File Symlink Rejection Test Concept

**What it tests**: Key files that are symlinks are rejected to prevent TOCTOU attacks.

The plugin loader (`src/plugin/axum_loader.rs:12`) explicitly checks for symlinks:
```rust
if metadata.file_type().is_symlink() {
    return Err("Plugin symlinks are not allowed".to_string());
}
```

**Test concept**:
1. Create a temporary directory with a legitimate plugin
2. Create a symlink at the plugin path pointing to a sensitive file (e.g., `/etc/passwd`)
3. Attempt to load the plugin
4. Verify the load is rejected with "Plugin symlinks are not allowed"

**Current state**: Symlink rejection exists in plugin loader for security reasons. This test
concept ensures it cannot be bypassed by refactoring.

### Runtime Dir Symlink Rejection Test Concept

**What it tests**: Runtime directories (pidfiles, sockets) cannot be redirected via symlinks.

PID file creation in `src/process/manager.rs:402` uses `create_new` to prevent symlink attacks:
```rust
// Try to create the file with create_new to prevent symlink attacks
let file = OpenOptions::new()
    .create_new(true)
    ...
```

**Test concept**:
1. Create a temporary directory
2. Create a symlink inside it pointing to a target file
3. Attempt to write a pidfile that would resolve through the symlink
4. Verify the write fails or the symlink is rejected

**Current state**: `create_new` prevents symlink attacks at pidfile creation. Runtime dir
creation should be verified to use this pattern consistently.

### Sandbox Strict-Mode Failure When Unsupported Test Concept

**What it tests**: When `SandboxLevel::Strict` is requested but the platform sandbox is
not supported, the system fails closed rather than falling back to a weaker mode.

The sandbox backend interface (`src/platform/sandbox.rs:37`) has `is_supported()` but the
strict-mode enforcement needs verification:

**Test concept**:
1. On a platform without Landlock support (or where sandbox is unavailable)
2. Request `SandboxLevel::Strict`
3. Verify that `is_supported()` returns `false`
4. Verify that `apply()` returns `SandboxError::NotSupported` or `LandlockUnavailable`
5. Verify the application does not start (fails closed) rather than starting with `Off` level

**Current state**: `SandboxError::LandlockUnavailable` exists for kernel < 5.13. The strict-mode
fallback behavior needs explicit testing.

## Unsafe Code Gates

### Miri for Buffer Pool Tests

The buffer pool (`src/buffer/pool.rs`) uses `unsafe` blocks for linked list manipulation:

```rust
unsafe {
    let next = (*head).next;
    ...
    let node = unsafe { Box::from_raw(head) };
}
```

**Miri command** (requires nightly):
```bash
cargo +nightly miri test --lib buffer
```

**Scope**: Focus on `TreiberStack` push/pop operations and buffer metadata handling.

### Stress Tests for Buffer Pool and IPC Framing

**Buffer pool stress test concepts**:
- Simultaneous acquire/release from multiple threads
- Buffer size boundary conditions (exact fit, overflow, underflow)
- Pool exhaustion and refill behavior
- Memory pattern verification after release

**IPC framing stress test concepts**:
- Large messages near `DEFAULT_BUFFER_SIZE` (64KB) limits
- Malformed header bytes
- Truncated messages mid-read
- Concurrent frame interleaving

## Example GitHub Actions Pipeline

```yaml
name: Systems CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  linux-default:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check default features
        run: |
          cargo check
          cargo test --lib
          cargo fmt --check
          cargo clippy --lib -- -D warnings

  linux-no-default:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check no-default-features
        run: |
          cargo check --no-default-features
          cargo check --no-default-features --features mesh
          cargo check --no-default-features --features dns
          cargo check --no-default-features --features mesh,dns

  linux-feature-socket-handoff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check socket-handoff feature
        run: cargo check --features socket-handoff

  linux-feature-icmp-filter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check icmp-filter feature
        run: cargo check --features icmp-filter

  macos-no-default:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check macOS no-default-features
        run: |
          cargo check --no-default-features --features mesh,dns

  windows-no-default:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check Windows no-default-features
        run: |
          cargo check --no-default-features --features mesh,dns

  # Security regression tests - run as integration tests
  security-regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Run security-sensitive tests
        run: |
          cargo test --test integration_test security::
          cargo test --lib -- ipc_signed
          cargo test --lib -- sandbox

  # Unsafe code gate (requires nightly)
  unsafe-gate:
    runs-on: ubuntu-latest
    if: false  # Enable when Miri testing is ready
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - name: Install Miri
        run: |
          rustup component add miri
          cargo miri setup
      - name: Run Miri on buffer pool
        run: cargo miri test --lib buffer
```

## Done Criteria

- [ ] CI or equivalent documented verification covers every claimed platform
- [ ] Security-sensitive systems-layer tests are part of normal validation
- [ ] Unsafe code gates documented and executable where feasible
- [ ] Platform-specific compile errors caught before merge
