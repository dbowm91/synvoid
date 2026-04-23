# Plan 35: Test Coverage Improvements

## Context

A systematic review of the MaluWAF codebase test coverage was conducted to verify tests are working as intended and the overseer/master/worker architecture is maintained. The review identified 7 issue areas: 1 failing test suite, 2 high-priority gaps, 3 medium-priority gaps, and 2 low-priority cleanup items.

**Scope**: Test coverage improvements for the overseer/master/worker architecture, DNS cache tests, drain timeout edge cases, StaticWorker, UnifiedServer, Windows IPC, and dead code cleanup.

---

## Executive Summary

### Test Suite Results

| Test Suite | Status | Passed | Failed |
|------------|--------|--------|--------|
| `integration_test` | ✅ | 242 | 0 |
| `e2e_process_test` | ✅ | 13 | 0 |
| `ipc_test` | ✅ | 143 | 0 |
| `drain_e2e_test` | ✅ | 4 | 0 |
| `process_lifecycle_test` | ✅ | 33 | 0 |
| `dht_integration_test` | ✅ | 90 | 0 |
| `dns_recursive_test` | ❌ | 33 | **3** |

### Architecture Verification

The overseer/master/worker architecture is verified through existing tests:

| Component | Location | Test Coverage |
|-----------|----------|---------------|
| **Overseer** | `src/overseer/` | `OverseerConfig`, `DrainManager`, `HealthChecker`, `SpawnConfig`, `UpgradeMode`, connection tracking |
| **Master** | `src/master/` | IPC message handling, worker lifecycle, graceful shutdown, drain protocol, multi-worker |
| **Worker** | `src/worker/` | `WorkerDrainState`, `WorkerMetrics`, IPC categories, `WorkerId`, heartbeat, shutdown |

### Issue Priority Matrix

| Priority | Item | Issue Type | Effort |
|----------|------|-----------|--------|
| **HIGH** | DNS cache `len()` bug | Failing tests | Medium |
| **HIGH** | Overseer→master IPC health check | Missing coverage | High |
| MEDIUM | Drain timeout edge cases | Missing coverage | Medium |
| MEDIUM | StaticWorker integration tests | Missing coverage | Medium-High |
| MEDIUM | UnifiedServer worker tests | Missing coverage | High |
| LOW | Windows named pipe IPC | Missing coverage | High (requires Windows) |
| LOW | Dead code warnings | Code cleanup | Low |

---

## Phase 1: Fix Failing DNS Cache Tests

### 1.1 Root Cause Analysis

**Issue**: `moka::sync::Cache::entry_count()` returns 0 while `get()` works correctly.

**Affected methods** (`src/dns/recursive_cache.rs`):

```rust
// Lines 326-342 - All return 0 despite cache having entries
pub fn len(&self) -> usize {
    self.inner.positive_cache.entry_count() as usize
        + self.inner.negative_cache.entry_count() as usize
}

pub fn positive_len(&self) -> usize {
    self.inner.positive_cache.entry_count() as usize
}

pub fn negative_len(&self) -> usize {
    self.inner.negative_cache.entry_count() as usize
}
```

**Failing tests** (`tests/dns_recursive_test.rs`):

| Test | Line | Assertion |
|------|------|----------|
| `test_cache_different_types_same_name` | 109 | `assert_eq!(cache.len(), 2)` |
| `test_cache_invalidation_all` | 168 | `assert_eq!(cache.len(), 3)` |
| `test_cache_positive_negative_separation` | 213 | `assert_eq!(cache.positive_len(), 2)` |

**Why it wasn't caught**: Unit tests in `src/dns/recursive_cache.rs:345-421` test `get()` and `stats()` but never call `len()`, `positive_len()`, or `negative_len()`.

### 1.2 Recommended Fix

Replace moka's `entry_count()` with manual counters:

```rust
pub struct RecursiveCache {
    positive_cache: Cache<RecursiveCacheKey, PositiveCacheEntry>,
    negative_cache: Cache<RecursiveCacheKey, NegativeCacheEntry>,
    positive_count: AtomicUsize,  // NEW
    negative_count: AtomicUsize,  // NEW
}

impl RecursiveCache {
    pub fn len(&self) -> usize {
        self.positive_count.load(Ordering::Relaxed)
            + self.negative_count.load(Ordering::Relaxed)
    }

    pub fn positive_len(&self) -> usize {
        self.positive_count.load(Ordering::Relaxed)
    }

    pub fn negative_len(&self) -> usize {
        self.negative_count.load(Ordering::Relaxed)
    }
}
```

**Files to modify**:
- `src/dns/recursive_cache.rs` - Add atomic counters, update `insert_positive()`, `insert_negative()`, `invalidate()`, `invalidate_all()`, `clear()` to manage counters

---

## Phase 2: Add Overseer→Master IPC Health Check Tests

### 2.1 Current Coverage

**Existing tests verify**:
- `MasterHealth` struct `is_healthy()` combinations (`tests/integration_test.rs:81-119`)
- `MasterHealthCheck` / `HealthCheckAck` message roundtrip (`tests/ipc_test.rs:764-767`)
- Unit tests for `OverseerProcess.check_master_health()` (`src/overseer/process.rs:1581-1688`) - **struct-level only, no actual IPC**

**What's missing**: No integration test that exercises actual IPC socket communication between overseer and master.

### 2.2 Key Methods Needing Integration Tests

| Method | Location | Purpose |
|--------|----------|---------|
| `check_master_health()` | `src/overseer/process.rs:83-117` | Process alive + IPC health |
| `check_master_ipc_health()` | `src/overseer/process.rs:119-167` | Socket connect, send `MasterHealthCheck`, recv `HealthCheckAck` |
| `send_upgrade_prepare()` | `src/overseer/process.rs:545-578` | Send `OverseerUpgradePrepare`, recv `OverseerUpgradePrepareAck` |
| `send_drain_workers()` | `src/overseer/process.rs:580-601` | Send `OverseerDrainWorkers`, recv `OverseerDrainWorkersAck` |
| `apply_upgrade()` | `src/overseer/process.rs:478-543` | Full simple upgrade flow |
| `dual_master_upgrade()` | `src/overseer/process.rs:717-837` | Dual-master with health validation |
| `abort_dual_master_upgrade()` | `src/overseer/process.rs:1384-1449` | Abort path with cleanup |

### 2.3 Recommended Test Scenarios

**New file**: `tests/overseer_health_check_test.rs`

| Test | Scenario |
|------|----------|
| `test_overseer_sends_master_health_check_and_receives_ack` | Mock master on socket, verify full roundtrip |
| `test_overseer_health_check_timeout_when_master_unresponsive` | Master doesn't respond within 5000ms |
| `test_overseer_health_check_connection_failure` | Socket not available |
| `test_overseer_health_check_with_wrong_response` | Master sends wrong message type |
| `test_send_upgrade_prepare_success` | Happy path for upgrade prepare |
| `test_send_upgrade_prepare_rejected` | Master rejects with error |
| `test_apply_upgrade_full_flow` | Integration test of entire flow |

**Test harness requirements**:
- Mock master process listening on master socket
- `IpcListener::bind()` + `accept()` pattern (already used in `e2e_process_test.rs`)
- Configurable response messages

### 2.4 Files to Create

```
tests/overseer_health_check_test.rs  (NEW)
```

---

## Phase 3: Add Drain Timeout Edge Case Tests

### 3.1 Current Coverage Gap

All existing drain tests are "happy path" - workers respond immediately. No timeout scenarios tested.

**Current tests** (`tests/drain_e2e_test.rs`):

| Test | What's Tested | Gap |
|------|---------------|-----|
| `test_worker_drain_protocol_basic` | Worker responds immediately | No timeout |
| `test_worker_drain_protocol_with_connections` | Worker responds with `remaining_connections: 5` | No timeout |
| `test_worker_drain_protocol_timeout` | **MISLEADING NAME** - Worker cooperates | Name is wrong, no actual timeout |
| `test_multiple_workers_drain_sequence` | 3 workers drain sequentially | No timeout |

### 3.2 Missing Test Scenarios

| # | Test Name | Scenario | Location to Add |
|---|----------|----------|-----------------|
| 1 | `test_worker_drain_request_timeout` | Worker receives drain but never responds with drained | `tests/drain_e2e_test.rs` |
| 2 | `test_worker_shutdown_complete_timeout` | Worker drains but never sends shutdown complete | `tests/drain_e2e_test.rs` |
| 3 | `test_drain_manager_poll_timeout` | DrainManager polls but worker never reaches drain_complete | `tests/drain_e2e_test.rs` |
| 4 | `test_overseer_drain_master_timeout` | Master doesn't respond to OverseerDrainWorkers | `tests/drain_e2e_test.rs` |
| 5 | `test_old_master_graceful_shutdown_timeout` | Master accepts drain but doesn't exit gracefully | `tests/e2e_process_test.rs` |
| 6 | `test_multiple_workers_mixed_timeout_behavior` | Some workers drain, some timeout | `tests/drain_e2e_test.rs` |
| 7 | `test_drain_rejected_different_drain_id` | Worker rejects drain due to mismatched drain_id | `tests/drain_e2e_test.rs` |

### 3.3 Key Code Paths

| Path | Location | Timeout Behavior |
|------|----------|-----------------|
| `drain_worker_async()` | `src/process/manager.rs:863-881` | Returns error string on timeout |
| `wait_for_drain()` | `src/worker/unified_server.rs:1593-1601` | Returns timeout error |
| `drain_worker_with_confirmation()` | `src/overseer/drain_manager.rs:321-360` | Returns `Ok(false)` on timeout |
| Old master shutdown | `src/overseer/process.rs:1061-1084` | Force kills with SIGTERM/SIGKILL |

### 3.4 Implementation Notes

For timeout tests, the mock worker should:
1. Accept connection
2. Send `WorkerStarted` / `WorkerReady`
3. **Never** send `WorkerDrained` (for scenario 1)
4. OR send `WorkerDrained` but never `WorkerShutdownComplete` (for scenario 2)

---

## Phase 4: Add StaticWorker Integration Tests

### 4.1 Current Coverage

**Unit tests exist** for:
- `StaticWorkerArgs` construction
- `CompressionTask` creation
- `ContentType` parsing
- `CacheKey` equality/hashing
- `MinifierCache` insert/get/invalidate/clear
- `MinifierGenerator` compression/minification

**NOT tested**: Full `run_static_worker()` async function (520+ lines)

### 4.2 StaticWorker Lifecycle

```
Start (94-134) → Ready (136-293) → Handle Requests (295-509) → Shutdown (511-518)
```

| Phase | IPC Sent | IPC Received |
|-------|----------|--------------|
| Start | `StaticWorkerStarted` | - |
| Ready | `StaticWorkerReady` | - |
| Handle | - | `MasterShutdown`, `MinifyRequest`, `GetCompressedRequest` |
| Shutdown | `StaticWorkerBackgroundTasksDone` | - |

### 4.3 Recommended Test Scenarios

| Priority | Test | Complexity |
|----------|------|------------|
| LOW | `test_static_worker_state_get_cache_stats` - Unit test for stats aggregation | Low |
| MEDIUM | `test_handle_minify_client_connection_message_dispatch` - Loop, dispatch, response | Medium |
| HIGH | `test_static_worker_full_lifecycle` - Start → Ready → Request → Shutdown with mock master | High |
| HIGH | `test_static_worker_minify_request_roundtrip` - File reading → minification → response | High |
| HIGH | `test_static_worker_shutdown_with_pending_queue` - Queue processing on drain | High |

### 4.4 Test Harness Requirements

1. **IPC Server Mock** - Mock master that binds Unix socket, expects lifecycle messages
2. **File System Setup** - Temp config dir with `main.toml`, sample HTML/CSS/JS
3. **IPC Key Handling** - Mock `IpcSigner::try_from_env()` or set env var

---

## Phase 5: Add UnifiedServer Worker Tests

### 5.1 Current Coverage

**Only serialization tests** (`tests/ipc_test.rs:1135-1201`):
- `test_roundtrip_unified_server_worker_started_full`
- `test_roundtrip_unified_server_worker_ready_full`
- `test_roundtrip_unified_server_worker_heartbeat_full`
- etc. (9 tests total - serialization only)

**NOT tested**: Actual worker lifecycle, IPC message handling, drain/resize operations

### 5.2 UnifiedServer Lifecycle

```
Start (161-1165) → Ready (1233-1546) → Handle Requests (1172-1218, 1552-1558) → Drain (1454-1496) → Shutdown (1276-1295)
```

| Phase | IPC Sent | IPC Received |
|-------|----------|--------------|
| Start | `UnifiedServerWorkerStarted` | - |
| Ready | `UnifiedServerWorkerReady` | - |
| Handle | Heartbeat (every 5s) | `MasterShutdown`, `MasterHealthCheck`, `BlocklistUpdate`, `RulePatternsUpdate`, `UnifiedServerWorkerDrain`, `UnifiedServerWorkerResize` |
| Drain | `UnifiedServerWorkerDrained` | - |
| Shutdown | `UnifiedServerWorkerShutdownComplete` | - |

### 5.3 Recommended Test Scenarios

| Priority | Test | Complexity |
|----------|------|------------|
| MEDIUM | `test_unified_server_blocklist_update_handling` - Blocklist message handling | Medium |
| MEDIUM | `test_unified_server_rule_patterns_update` - WAF rules update | Medium |
| MEDIUM | `test_unified_server_resize_ack` - Threadpool resize acknowledgment | Medium |
| HIGH | `test_unified_server_full_lifecycle` - Start → Ready → Handle → Drain → Shutdown | High |
| HIGH | `test_unified_server_health_check_response` - MasterHealthCheck → HealthCheckAck | Medium |
| HIGH | `test_unified_server_multiple_workers` - Multi-worker IPC | High |

### 5.4 Process Manager Methods Needing Tests

| Method | Location | Purpose |
|--------|----------|---------|
| `drain_unified_server_worker_async()` | `src/process/manager.rs:811-841` | Drain worker with timeout |
| `resize_unified_server_worker_threadpool_internal()` | `src/process/manager.rs:1852-1905` | Threadpool resize |

---

## Phase 6: Windows Named Pipe IPC Tests

### 6.1 Current State

**Zero test coverage** for Windows named pipe IPC. All socket tests use `#[cfg(unix)]`.

**Infrastructure exists but untested**:

| File | Lines | Purpose |
|------|-------|---------|
| `src/process/ipc_windows.rs` | 113 | Low-level named pipe helpers |
| `src/master/windows.rs` | 241 | Master IPC accept loop |
| `src/platform/windows_impl.rs` | 190-329 | Platform IPC traits |

**Named pipes**:
- `\\.\pipe\maluwaf-master`
- `\\.\pipe\maluwaf-static-worker`
- `\\.\pipe\maluwaf-commands`
- `\\.\pipe\maluwaf-socket-handoff`

### 6.2 Unix-Only Tests Needing Windows Equivalents

| File | Test | Windows Equivalent |
|------|------|-------------------|
| `tests/ipc_test.rs` | `test_ipc_unix_socket_send_recv` | Named pipe server/client |
| `tests/ipc_test.rs` | `test_ipc_multiple_messages` | Sequential exchange |
| `tests/ipc_test.rs` | `test_ipc_bidirectional_communication` | Full lifecycle |
| `tests/e2e_process_test.rs` | All 13 tests | Named pipe equivalent |
| `tests/drain_e2e_test.rs` | All 4 tests | Named pipe equivalent |

### 6.3 Recommendation

**Conditional test module approach**:

```rust
#[cfg(unix)]
mod ipc_transport_tests {
    // Unix socket tests
}

#[cfg(windows)]
mod ipc_transport_tests {
    // Named pipe tests - same patterns, different setup
}
```

**Alternative**: Use `#[cfg_attr(windows, ignore)]` on existing tests and add Windows-specific tests.

**Note**: Full Windows testing requires Windows OS or CI runner with Windows. Document that these tests are CI-gated.

---

## Phase 7: Fix Dead Code Warnings in Integration Tests

### 7.1 Root Cause

**Nested `#[cfg(test)]` modules** inside outer `mod tests { ... }` at `tests/integration_test.rs`.

**Problem structure**:
```rust
#[cfg(test)]          // Line 4
mod tests {           // Outer module
    #[cfg(test)]     // Line 427 - NESTED, creates separate test crate
    mod waf_body_inspection_tests { ... }  // Unreachable!

    #[cfg(test)]     // Line 478
    mod dnssec_validation_tests { ... }     // Unreachable!
    // ... 6 nested modules total
}
```

**42 valid test functions** cannot be discovered by Rust's test runner.

### 7.2 Affected Functions (42 total)

| Module | Lines | Functions |
|--------|-------|-----------|
| `waf_body_inspection_tests` | 427-476 | 6 |
| `dnssec_validation_tests` | 478-641 | 15 |
| `upload_scanning_tests` | 643-662 | 3 |
| `mesh_threat_propagation_tests` | 664-708 | 4 |
| `honeypot_mesh_flow_tests` | 710-730 | 2 |
| `yara_mesh_distribution_tests` | 732-852 | 12 |

### 7.3 Recommended Fix

**Option A**: Remove outer `mod tests` wrapper (lines 4-5, 853 closing brace)

**Option B**: Remove `#[cfg(test)]` from nested modules, making them regular submodules

**Option B is preferred** - maintains organization while making tests discoverable:

```rust
// BEFORE (broken)
#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod waf_body_inspection_tests { ... }
}

// AFTER (working)
#[cfg(test)]
mod tests { ... }

// Top-level sibling modules (correct structure)
#[cfg(test)]
mod waf_body_inspection_tests { ... }

#[cfg(test)]
mod dnssec_validation_tests { ... }
```

### 7.4 Files to Modify

- `tests/integration_test.rs` - Restructure module hierarchy

---

## Implementation Order

| Priority | Phase | Item | Effort | Files |
|----------|-------|------|--------|-------|
| **HIGH** | 1 | Fix DNS cache `len()` bug | Medium | `src/dns/recursive_cache.rs` |
| LOW | 7 | Fix dead code warnings | Low | `tests/integration_test.rs` |
| MEDIUM | 3 | Add drain timeout edge cases | Medium | `tests/drain_e2e_test.rs` |
| MEDIUM | 4 | Add StaticWorker integration tests | Medium-High | New file |
| **HIGH** | 2 | Add overseer→master IPC tests | High | New file |
| MEDIUM | 5 | Add UnifiedServer worker tests | High | New file |
| LOW | 6 | Add Windows IPC tests | High (CI-gated) | Conditional modules |

### Recommended Start Order

1. **Phase 1 (DNS cache bug)** - Fix failing tests first (HIGH priority, failing)
2. **Phase 7 (dead code cleanup)** - Trivial fix, improves CI output (LOW priority)
3. **Phase 3 (drain timeouts)** - Architecture-critical, moderate effort (MEDIUM priority)
4. **Phase 4 (StaticWorker)** - Smaller scope, good for incremental progress (MEDIUM priority)
5. **Phase 2 (overseer IPC)** - High value, high effort (HIGH priority)
6. **Phase 5 (UnifiedServer)** - High effort, lower priority (MEDIUM priority)
7. **Phase 6 (Windows IPC)** - CI-gated, defer unless Windows CI available (LOW priority)

---

## Verification

### After DNS Cache Fix
```bash
cargo test --test dns_recursive_test
# Should show: test result: ok. 36 passed; 0 failed
```

### After Dead Code Cleanup
```bash
cargo test --test integration_test --no-run 2>&1 | grep -E "warning:|never used"
# Should show: 0 warnings
```

### After Drain Timeout Tests
```bash
cargo test --test drain_e2e_test
# Should show: 11 tests (4 existing + 7 new)
```

### After All Phases
```bash
cargo test --test integration_test
cargo test --test e2e_process_test
cargo test --test ipc_test
cargo test --test drain_e2e_test
cargo test --test process_lifecycle_test
cargo test --test dht_integration_test
cargo test --test dns_recursive_test
# All should pass with 0 failures
```

---

## Files Summary

### Code Changes

| File | Phase | Change |
|------|-------|--------|
| `src/dns/recursive_cache.rs` | 1 | Add atomic counters for len/positive_len/negative_len |
| `tests/integration_test.rs` | 7 | Restructure module hierarchy to fix dead code warnings |

### New Test Files

| File | Phase | Purpose |
|------|-------|---------|
| `tests/overseer_health_check_test.rs` | 2 | Overseer→master IPC health check tests |
| `tests/static_worker_test.rs` | 4 | StaticWorker integration tests |
| `tests/unified_server_test.rs` | 5 | UnifiedServer worker tests |
| `tests/windows_ipc_test.rs` | 6 | Windows named pipe IPC tests |

### Enhanced Test Files

| File | Phase | Changes |
|------|-------|---------|
| `tests/drain_e2e_test.rs` | 3 | Add 7 drain timeout edge case tests |
| `tests/integration_test.rs` | 7 | Fix module structure (dead code fix) |

---

## Appendix: Test Architecture Notes

### IPC Test Pattern (Reference)

All IPC integration tests follow this pattern:

```rust
#[tokio::test]
async fn test_ipc_scenario() {
    let temp_dir = TempDir::new().unwrap();
    let endpoint = temp_endpoint(&temp_dir, "test-name");

    // Server: bind listener
    let listener = IpcListener::bind(&endpoint).await.unwrap();

    // Client: connect in background
    let client_handle = tokio::spawn(async move {
        let mut stream = endpoint.connect().await.unwrap();
        stream.send(&message).await.unwrap();
        // ...
    });

    // Server: accept and verify
    let mut server_stream = listener.accept().await.unwrap();
    let received: Message = server_stream.recv().await.unwrap().unwrap();
    assert!(matches!(received, Message::WorkerStarted { .. }));

    client_handle.await.unwrap();
}
```

### Message Category Reference

| Category | Messages |
|----------|----------|
| `WorkerLifecycle` | `WorkerStarted`, `WorkerReady`, `WorkerHeartbeat`, `WorkerShutdownComplete` |
| `MasterCommand` | `MasterShutdown`, `MasterConfigReload`, `MasterResizeThreadpool` |
| `WorkerDrain` | `WorkerDrain`, `WorkerDrained`, `WorkerDrainComplete` |
| `Overseer` | `OverseerGetStatus`, `OverseerDrainWorkers` |
| `Upgrade` | `UpgradeReady`, `UpgradeFailed`, `OverseerUpgradePrepare` |

---

## References

- AGENTS.md - Testing patterns and test categories
- `tests/integration_test.rs` - Reference for module structure issues
- `src/dns/recursive_cache.rs` - Cache implementation
- `src/overseer/process.rs` - Overseer health check implementation
- `src/worker/drain_state.rs` - Worker drain state machine
- `src/process/manager.rs` - Process manager drain logic
