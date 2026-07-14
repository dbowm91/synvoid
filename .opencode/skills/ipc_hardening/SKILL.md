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

**Location**: `src/process/ipc_signed.rs:108`

```rust
pub struct IpcSigner {
    key: [u8; 32],
}

impl IpcSigner {
    /// Sign data with HMAC-SHA3-256
    pub fn sign(&self, data: &[u8]) -> Vec<u8>;

    /// Sign multiple parts without concatenation (zero-copy)
    pub fn sign_parts(&self, parts: &[&[u8]]) -> Vec<u8>;

    /// Verify HMAC (uses subtle::ConstantTimeEq)
    pub fn verify(&self, data: &[u8], expected: &[u8]) -> bool;

    /// Verify multiple parts
    pub fn verify_parts(&self, parts: &[&[u8]], expected: &[u8]) -> bool;
}
```

### Key Loading

Keys can be loaded from:
1. **File** (`SYNVOID_IPC_KEY_FILE`): 64 hex chars, deleted after reading
2. **Env** (`SYNVOID_IPC_KEY`): 64 hex chars directly
3. **Secret** (`IpcSigner::from_secret()`): SHA-256 of string — **TEST/DEV ONLY**

Unix key file uses `O_EXCL | O_NOFOLLOW` to prevent symlink attacks.

### Replay Protection

**Location**: `src/process/ipc_signed.rs:45-106`

```rust
const MAX_NONCE_CACHE_SIZE: usize = 10_000;
const REPLAY_WINDOW_SECS: u64 = 60;
```

- Nonce cache uses `DashMap` for sharded concurrent access (reduced contention)
- Cache key is `(signer_id, nonce)` tuple to prevent cross-channel conflicts
- Eviction happens BEFORE insert when size limit reached
- Timestamp must be within 60 seconds of current time

### Message Size Limits

**Centralized constant**: `MAX_IPC_MESSAGE_SIZE = 1024 * 1024` (1 MiB)

Use `crate::process::ipc_signed::MAX_IPC_MESSAGE_SIZE` for all size checks.

## Usage Patterns

### Creating a Signed Connection

```rust
use crate::process::ipc_transport::{IpcStream, IpcSigner};

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
4. **No hardcoded secrets**: `from_secret()` is documented as TEST ONLY with SHA-256 KDF
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