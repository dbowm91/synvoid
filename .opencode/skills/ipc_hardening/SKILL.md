---
name: ipc_hardening
description: IPC signing, replay protection, authentication patterns, and inter-process communication security.
---

# IPC Hardening Patterns

This skill documents the IPC signing, replay protection, and authentication patterns in the SynVoid codebase.

## Overview

SynVoid uses signed IPC for privileged operations with HMAC-SHA3-256 verification and bounded replay protection.

## Wire Format

```
[4 bytes: total_len (u32 BE)]
[8 bytes: timestamp (u64 BE)]
[16 bytes: nonce]
[32 bytes: HMAC-SHA3-256 of timestamp+nonce+payload]
[N bytes: serialized payload]
```

## Core Components

### IpcSigner

**Location**: `crates/synvoid-ipc/src/ipc_signed.rs:162` (`synvoid_ipc::ipc_signed`;
`src/process/` is only a 6-line facade — never import `crate::process::ipc_*` paths)

```rust
pub struct IpcSigner {
    signer_id: u64,
    key: [u8; 32],
}

impl IpcSigner {
    /// Sign data with HMAC-SHA3-256 (fixed-size output, not Vec)
    pub fn sign(&self, data: &[u8]) -> [u8; HMAC_SIZE];

    /// Sign multiple parts without concatenation (zero-copy)
    pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; HMAC_SIZE];

    /// Verify HMAC (uses subtle::ConstantTimeEq)
    pub fn verify(&self, data: &[u8], expected_hmac: &[u8; HMAC_SIZE]) -> bool;

    /// Verify multiple parts
    pub fn verify_parts(&self, parts: &[&[u8]], expected_hmac: &[u8; HMAC_SIZE]) -> bool;
}
```

### Key Loading

Keys can be loaded from:
1. **File** (`SYNVOID_IPC_KEY_FILE`): 64 hex chars, deleted after reading
2. **Env** (`SYNVOID_IPC_KEY`): 64 hex chars directly
3. **Secret** (`IpcSigner::from_secret()`): SHA-256 of string — **`#[cfg(test)]` ONLY,
   not compiled into production binaries at all**

Unix key file uses `O_EXCL | O_NOFOLLOW` to prevent symlink attacks.

### Replay Protection

**Location**: `crates/synvoid-ipc/src/ipc_signed.rs:66-133`

```rust
const MAX_NONCE_CACHE_SIZE: usize = 10_000;
const REPLAY_WINDOW_SECS: u64 = 60;
```

- Nonce cache is a `DashMap<(signer_id, nonce), timestamp>` (`ShardedNonceCache`)
  for sharded concurrent access (reduced contention)
- Cache key is `(signer_id, nonce)` tuple to prevent cross-channel conflicts
- Duplicate check + insert is atomic via DashMap's entry API; capacity guard
  (`NONCE_CACHE_CAPACITY_LOCK`) serializes eviction: time-based `retain()` first,
  then single-entry eviction if still full
- Timestamp must be within 60 seconds of current time

### Message Size Limits

**Centralized constant**: `MAX_IPC_MESSAGE_SIZE = 1024 * 1024` (1 MiB)
(`crates/synvoid-ipc/src/ipc_signed.rs:51`; re-exported for framing as
`synvoid_ipc::ipc_framing::MAX_MESSAGE_SIZE`)

Use `synvoid_ipc::ipc_signed::MAX_IPC_MESSAGE_SIZE` for all size checks.

## Usage Patterns

### Creating a Signed Connection

```rust
use synvoid_ipc::ipc_transport::{IpcStream, IpcSigner};

let signer = IpcSigner::try_from_env()?;
let stream = IpcStream::connect_with_signer(endpoint, signer).await?;
```

### Verifying Incoming Commands

```rust
// For privileged commands (Stop, ReloadConfig)
match SignedIpcMessage::deserialize_signed(&mut stream, &signer) {
    Ok(msg) => handle_privileged_command(msg),
    Err(_) => {
        log::warn!("Unsigned or invalid signature rejected");
        return Err("Authentication required");
    }
}
```

### Unsigned Connections

Unsigned IPC is allowed for read-only operations (Status, HealthCheck) but:
- Privileged commands (Stop, ReloadConfig) are REJECTED without signature
- Warning logs are emitted for unsigned connections

## Security Notes

1. **Constant-time comparison**: Always use `subtle::ConstantTimeEq` for HMAC verification
2. **Bounded cache**: Nonce cache is bounded to 10,000 entries, keyed by `(signer_id, nonce)`
3. **Key file security**: Files must be owned by current user, mode 0600, not symlinks, not in world-writable directories
4. **No hardcoded secrets**: `from_secret()` is `#[cfg(test)]` — unavailable in production builds
5. **Windows Security**: `SecurityDescriptor::new_user_only()` creates DACLs granting `FILE_ALL_ACCESS` only to current user
6. **Signing enforced by default**: `enforce_signing=true` is default for `IpcStream` with explicit signer constructors

## Testing

```rust
// Key file symlink rejection
#[test]
fn test_key_file_symlink_rejected() {
    let tmpdir = TempDir::new().unwrap();
    let symlink = tmpdir.path().join("key");
    std::os::unix::fs::symlink("../../../etc/passwd", &symlink).unwrap();
    let result = IpcSigner::from_file(symlink);
    assert!(result.is_err());
}
```

## Verification Commands

```bash
cargo test --lib ipc_signed
cargo test --lib ipc_framing
cargo test -p synvoid-ipc --test ipc_test
cargo test -p synvoid-ipc --test process_lifecycle_test
```