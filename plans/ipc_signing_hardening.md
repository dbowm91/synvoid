# IPC Signing Hardening

**Priority**: 3
**Status**: Documented

## Overview

This document describes issues found in `src/process/ipc_signed.rs` and the fixes needed to harden IPC signing, replay cache, and key handling.

## Issues Found

### 1. Replay Cache: Global Mutex and Eviction-Before-Insert Bug

**Location**: `src/process/ipc_signed.rs:77-92`

**Problem 1 - Global mutex**:
The replay cache uses a single `static NONCE_CACHE: LazyLock<parking_lot::Mutex<NonceCache>>` protected by one global mutex. This means all signers and all channels share the same cache with a single lock. At high scale (1000K RPS), this creates a contention point.

**Problem 2 - Eviction before insert**:
At line 89, `cache.evict_oldest()` is called **before** `cache.insert()`. The evict function removes entries while the size is `> MAX_NONCE_CACHE_SIZE`. So after the first insert, the cache has 1 entry, eviction doesn't run, insert happens, cache has 1 entry. After second insert, cache has 2 entries, eviction removes oldest (since 2 > 1), then insert happens... wait, let me re-read.

Actually the code is:
```rust
cache.evict_oldest();  // removes entries while len > 10000
cache.insert(*nonce, timestamp);
```

The evict condition is `while self.by_timestamp.len() > MAX_NONCE_CACHE_SIZE`. So after the first insert, size is 1. Next insert: size is 2, no eviction (2 > 1 is false), insert, size is 2. Wait, that doesn't exceed either.

Let me trace through more carefully:
- Start: empty (size 0)
- Insert 1: no eviction (0 > 10000 is false), insert, size = 1
- Insert 2: no eviction (1 > 10000 is false), insert, size = 2
- ...
- Insert 10001: no eviction (10000 > 10000 is false), insert, size = 10001

So the cache exceeds capacity by 1 entry on every insert once we hit the limit. The bug is that eviction happens BEFORE insert, so the size can be `MAX + 1` momentarily before the old entry is removed.

**Problem 3 - No channel/signer distinction**:
The cache key is just the nonce (`[u8; 16]`). If two different channels use the same nonce value (but different signers or different contexts), the second one will be rejected as a replay even though it's legitimate.

### 2. Key File Loading: Missing Symlink/Permission Checks on Unix

**Location**: `src/process/ipc_signed.rs:598-635` and `try_from_env() at lines 127-203`

**Problems**:
- `try_from_env()` at line 132-135 uses `O_EXCL` but NOT `O_NOFOLLOW`. A symlink attack could point to a different file.
- `read_ipc_key_file_impl()` at line 605 does use `O_NOFOLLOW` (good), but only on Unix.
- Permission checks: The code opens files but doesn't verify ownership or permissions before reading.
- File deletion after failed read: At line 144 and 614, the key file is deleted even if the read failed, which may not be the intended behavior.

**Missing checks**:
1. No verification that the file owner matches the process user
2. No check that permissions are restrictive (e.g., 0o600 or 0o400)
3. No verification that the file is a regular file (not device, socket, etc.)
4. The non-Unix path (`read_ipc_key_file_impl` at 638-660) has NO protections at all

### 3. Duplicated Hex Parsing

**Locations**: Multiple places

**Problem**: The hex parsing logic is duplicated in at least 3 places:
1. `try_from_env()` lines 149-170 (for file key)
2. `try_from_env()` lines 179-199 (for env var key)
3. `read_ipc_key_file_impl()` lines 621-633 (for Unix)
4. `read_ipc_key_file_impl()` lines 646-658 (for non-Unix)

Each is slightly different - some use `valid` flag, some use early return. They all do the same thing: parse 64 hex characters into `[u8; 32]`.

### 4. `from_secret()` Lacks KDF Parameters

**Location**: `src/process/ipc_signed.rs:117-125`

**Problem**: The `from_secret()` function takes an arbitrary string and hashes it with SHA-256 without any KDF parameters (no salt, no iterations, no work factor). This is problematic because:
1. Users may use weak passwords
2. No computational work factor means offline brute force is easy
3. No salt means identical secrets produce identical keys

This function should either:
- Be documented as test/dev only
- Be replaced with a proper KDF (e.g., Argon2, scrypt, or at minimum PBKDF2 with parameters)

## Fixes Needed

### 1. Bounded Replay Cache with Channel-Aware Keys

**Approach**:
- Change cache key to include `(signer_id, channel_id, nonce)` tuple
- Consider per-signer or per-channel cache to reduce lock contention
- Evict AFTER insert, not before, to guarantee bounded size
- Alternatively, use a ring buffer or fixed-size structure

**Implementation suggestion**:
```rust
// Per-signer cache with bounded size
struct SignerNonceCache {
    entries: VecDeque<(Nonce, u64)>,  // nonce + timestamp
}

impl SignerNonceCache {
    fn new(max_size: usize) -> Self;
    fn check_and_insert(&mut self, nonce: Nonce, timestamp: u64) -> bool;
}
```

### 2. Symlink and Permission Checks for Key Files

**Approach**:
- Unix: use `O_NOFOLLOW`, check file type with `FileType`, verify owner (uid check), verify mode (0o600 or stricter)
- Windows: either implement proper ACL checks or explicitly document as unsupported
- Don't delete file until AFTER validation passes

**Implementation suggestion**:
```rust
#[cfg(unix)]
fn validate_key_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    // Verify regular file
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "not a regular file"));
    }
    // Verify permissions 0o600 or 0o400
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "world accessible"));
    }
    // Verify owner matches current user or is root
    // ... owner check ...
    Ok(())
}
```

### 3. One Canonical Hex Parsing Path

**Approach**:
- Create a single `fn parse_hex_key(hex: &str) -> Option<[u8; 32]>` helper
- Use constant-time comparison for key comparison if needed later
- Have all key loading paths use this helper

### 4. Document or Replace `from_secret()`

**Approach**:
- Add documentation that this is for test/dev only
- Or replace with a KDF helper accepting salt and iterations
- Production should use `generate_session_key()` which uses OsRng

## Tests Needed

1. **Short read test**: Ensure signed reader returns `UnexpectedEof` on short frame reads, not partial parse
2. **Cache capacity test**: Verify cache stays bounded (doesn't exceed max by 1)
3. **Channel distinction test**: Same nonce on different channels should be handled correctly
4. **Symlink rejection test**: Key file that's a symlink should be rejected on Unix
5. **Permission rejection test**: Key file with 0o644 should be rejected
6. **Invalid hex test**: All loading paths should reject invalid hex consistently

## Done Criteria

- [ ] One key parsing path
- [ ] Replay cache is bounded and channel-aware
- [ ] Signed reads use `read_exact()` for frame data
- [ ] Key-file handoff is secure or explicitly unsupported on platforms where it cannot be made safe
- [ ] All tests pass