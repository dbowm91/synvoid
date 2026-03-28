# Test Coverage Improvement Plan

## Executive Summary

This plan addresses test coverage gaps and fixes broken unit tests in the MaluWAF codebase while maintaining the overseer/master/worker architecture integrity.

**Current Status:**
- Integration Tests: 40 passing
- IPC Tests: 6 passing  
- DNS Config Tests: 20+ passing
- Property Tests (DNS): 8+ passing
- Unit Tests: 14 compilation errors (blocking ~160 test modules)

---

## Phase 1: Fix Broken Unit Tests (Priority: CRITICAL)

### 1.1 Issue Analysis

**Location:** `src/mesh/config.rs` lines 1340-1447 (tests in `#[cfg(test)] mod tests`)
**Problem:** Tests call private methods from `src/mesh/config_identity.rs`
**Root Cause:** Methods `derive_encryption_key`, `encrypt_key`, `decrypt_key` are `fn` (private) instead of `pub(crate)`
**Affected File for Fix:** `src/mesh/config_identity.rs`

### 1.2 Fix Required

**File:** `src/mesh/config_identity.rs`

Change visibility of three methods from `fn` to `pub(crate)`:

```rust
// Line 251
fn derive_encryption_key(passphrase: &str) -> [u8; 32]
// Change to:
pub(crate) fn derive_encryption_key(passphrase: &str) -> [u8; 32]

// Line 259  
fn encrypt_key(&self, plaintext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String>
// Change to:
pub(crate) fn encrypt_key(&self, plaintext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String>

// Line 289
fn decrypt_key(&self, ciphertext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String>
// Change to:
pub(crate) fn decrypt_key(&self, ciphertext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String>
```

### 1.3 Verification

```bash
cargo test --lib  # Must compile and pass
```

---

## Phase 2: Architecture Integration Tests

### 2.1 Worker Status Transition Tests

**Purpose:** Verify worker status transitions are correct

**File:** `tests/integration_test.rs` (existing test already covers enum variants)

**Enhancement:** Add `is_*` method tests for each status

```rust
#[test]
fn test_worker_status_is_methods() {
    use maluwaf::supervisor::worker::WorkerStatus;
    
    assert!(WorkerStatus::Starting.is_starting());
    assert!(!WorkerStatus::Starting.is_running());
    assert!(WorkerStatus::Running.is_running());
    assert!(WorkerStatus::Ready.is_ready());
    assert!(WorkerStatus::Stopping.is_stopping());
    assert!(WorkerStatus::Stopped.is_stopped());
    assert!(WorkerStatus::Failed.is_failed());
}
```

**Current Status:** Basic enum test exists in `test_worker_status_enum` - this enhancement adds method coverage

### 2.2 IPC Socket Health Check Test

**Purpose:** Test actual socket-based health check between overseer and master

**File:** `tests/ipc_test.rs` (add new test)

**Note:** Existing `test_master_health_check` tests MasterHealth struct (not IPC). This enhancement adds socket-level test.

```rust
#[tokio::test]
async fn test_ipc_health_check_message_roundtrip() {
    // 1. Create paired Unix sockets (server/client)
    // 2. Server sends MasterHealthCheck message
    // 3. Client receives, sends HealthCheckAck  
    // 4. Verify roundtrip works
    use maluwaf::process::{Message, IpcStream};
}
```

**Current Coverage:** Struct-level test exists in `test_master_health_check` - this enhancement adds IPC message coverage

**Risk:** Medium - requires socket pair setup, may be flaky

### 2.3 IPC Signed Message Rejection Tests

**File:** `tests/ipc_test.rs` - Already exists!

**Current Coverage:** `test_ipc_signed_message_hmac_verification` (lines 154-180) covers:
- ✓ Correct key works (roundtrip)
- ✓ Wrong key fails
- ✓ Tampered message fails

**Status:** COMPLETE - No additional tests needed

---

## Phase 3: Enhance Existing Test Coverage

### 3.1 Drain State Transitions (Worker)

**File:** `tests/integration_test.rs` - extend `test_drain_state_transitions`

Add tests for:
- Drain completion callback
- Multiple concurrent drains
- Drain timeout handling

### 3.2 Overseer Upgrade Mode

**File:** `tests/integration_test.rs` - extend `test_upgrade_mode_detection`

Add tests for:
- Port swap offset calculation
- Dual master socket cleanup
- Versioned socket generation

### 3.3 Connection Tracking

**File:** `tests/integration_test.rs` - extend `test_connection_tracker`

Add tests for:
- Multi-worker connection counting
- Connection decay/expiry
- Overflow handling

---

## Phase 4: Documentation & Verification

### 4.1 Update AGENTS.md

Add test categories to reflect new tests:

```
| Integration Tests (Architecture) | `cargo test --test integration_test` | ~45 tests |
```

### 4.2 Run Full Test Suite

```bash
# All tests must pass
cargo test --test integration_test
cargo test --test ipc_test  
cargo test --test dns_config_test
cargo test --lib

# Integration test count verification
cargo test --test integration_test -- --list | wc -l
```

---

## Implementation Order

1. **Phase 1** - Fix 3 methods in `config_identity.rs` (15 min)
2. **Phase 2.1** - Enhance worker status tests with `is_*` methods (10 min)
3. **Phase 2.2** - Add IPC health check message test (15 min)
4. **Phase 2.3** - ALREADY COMPLETE - skip
5. **Phase 3** - Enhance drain, upgrade, connection tests (30 min)
6. **Phase 4** - Verify and document (15 min)

**Total Estimated Time:** ~1.5 hours

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking private API changes | Low | Only expanding visibility to pub(crate) |
| Test flakiness | Medium | Use realistic timeouts, avoid sleep-based tests |
| Socket conflicts | Medium | Use TempDir for all socket paths |

---

## Success Criteria

- [ ] `cargo test --lib` compiles and passes
- [ ] Integration tests increase from 40 to 42+ (worker status is_* methods)
- [ ] IPC tests increase from 6 to 7 (health check message roundtrip)
- [ ] All overseer/master/worker IPC paths have basic test coverage
- [ ] IPC signed message security verified (already complete)
- [ ] AGENTS.md updated with new test counts
